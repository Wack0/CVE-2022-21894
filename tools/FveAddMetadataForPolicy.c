// given a fve volume, insert the correct metadata.
// talks to fveapi directly.
// for a mounted vhd, doesn't even need admin(!!!)
#include <windows.h>
#include <stdbool.h>
#include <stdio.h>

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

// Opens an FVE encrypted volume.
typedef HRESULT (*fpFveOpenVolumeW)(LPWSTR volume, bool check, HANDLE* phFve);
// Writes dataset changes to an FVE encrypted volume.
typedef HRESULT (*fpFveCommitChanges)(HANDLE phFve);
// Closes an FVE encrypted volume.
typedef HRESULT (*fpFveCloseVolume)(HANDLE phFve);

// fve handle is a pointer to a CFveApiBase XORed with this
#define HANDLE_KEY (0xE1AB7F0DF794A1C5ui64)

// Structures we want.
// BitLocker metadata header. (BitLocker Drive Encryption (BDE) format.asciidoc 5.2)
typedef struct _FVE_DATASET
{
  unsigned int DataSetSize;
  unsigned int DataSetVersion;
  unsigned int DataSetStart;
  unsigned int DataSetEnd;
  GUID FveIdentification;
  unsigned int NonceCounter;
  unsigned __int16 FvekType;
  unsigned __int16 FvekPrefType;
  FILETIME DateTime;
} FVE_DATASET, *PFVE_DATASET;

// BitLocker metadata entry header. (BitLocker Drive Encryption (BDE) format.asciidoc 5.3)
typedef struct  _FVE_DATUM
{
  WORD StructureSize;
  WORD Role;
  WORD Type;
  WORD Flags;
} FVE_DATUM, *PFVE_DATUM, **PPFVE_DATUM;

// BitLocker key metadata blob. (BitLocker Drive Encryption (BDE) format.asciidoc 5.4)
typedef __unaligned __declspec(align(1)) struct _FVE_DATUM_KEY
{
  FVE_DATUM h;
  WORD KeyType;
  WORD KeyFlags; // bit 0 internally used as "derived from TPM, ensure secureboot policy flag bit2 is set", but not ever set elsewhere...
  WORD KeyData[1];
} FVE_DATUM_KEY, *PFVE_DATUM_KEY;

typedef __unaligned __declspec(align(4)) struct _FVE_DATUM_VMK_INFO
{
  FVE_DATUM h;
  GUID Identifier;
  FILETIME DateTime;
  WORD VmkHints;
  WORD Priority;
} FVE_DATUM_VMK_INFO, *PFVE_DATUM_VMK_INFO;


// Internal functions.
// Gets the offset of the next entry in this set of metadata.
typedef NTSTATUS (*fpFveDatasetGetNext)(const FVE_DATASET *DataSet, WORD Role, WORD Type, unsigned int Start, unsigned int *Next);
// Gets a pointer to the metadata entry with a specified offset in this set of metadata.
typedef NTSTATUS (*fpFveDatasetGetDatumPointer)(const FVE_DATASET *DataSet, unsigned int Offset, FVE_DATUM **Datum);
// Gets the offset of the next sub-entry in this metadata entry.
typedef NTSTATUS (*fpFveDatumNestedGetNext)(const FVE_DATUM *Datum, WORD Role, WORD Type, WORD Start, WORD *Next);
// Adds a metadata entry to a set of metadata.
typedef NTSTATUS (*fpFveDatasetAppendDatum)(FVE_DATASET *DataSet, const FVE_DATUM *Datum, WORD Role);


// Offsets to interesting things.
#define OFFSET_DATASET 0x270 // << CFveApiBase::m_pDataSet
#define OFFSET_FVE_DATASET_GET_NEXT 0xF524
#define OFFSET_FVE_DATASET_GET_DATUM_POINTER 0xB0034
#define OFFSET_FVE_DATUM_NESTED_GET_NEXT 0xF658
#define OFFSET_FVE_DATASET_APPEND_DATUM 0xD878

#define POINTER_FROM_OFFSET(base, offset) (void*) ( (size_t)(base) + (offset) )
#define DYNAMIC_LINK(base, export) fp##export export = ( fp##export ) GetProcAddress(base, #export )
#define DYNAMIC_LINK_OFFSET(base, offset, name) fp##name name = ( fp##name ) POINTER_FROM_OFFSET(base, offset)

int wmain(int argc, wchar_t** argv) {
	if (argc < 2) return 0;
	HMODULE FveApi = LoadLibraryW(L"fveapi.dll");
	if (FveApi == NULL) { printf("LoadLibrary(fveapi) failed %d", GetLastError()); return 0; }
	DYNAMIC_LINK(FveApi, FveOpenVolumeW);
	if (FveOpenVolumeW == NULL) { printf("GetProcAddress(fveapi, FveOpenVolumeW) failed %d", GetLastError()); return 0; }
	DYNAMIC_LINK(FveApi, FveCommitChanges);
	if (FveCommitChanges == NULL) { printf("GetProcAddress(fveapi, FveCommitChanges) failed %d", GetLastError()); return 0; }
	DYNAMIC_LINK(FveApi, FveCloseVolume);
	if (FveCloseVolume == NULL) { printf("GetProcAddress(fveapi, FveCloseVolume) failed %d", GetLastError()); return 0; }
	
	DYNAMIC_LINK_OFFSET(FveApi, OFFSET_FVE_DATASET_GET_NEXT, FveDatasetGetNext);
	DYNAMIC_LINK_OFFSET(FveApi, OFFSET_FVE_DATASET_GET_DATUM_POINTER, FveDatasetGetDatumPointer);
	DYNAMIC_LINK_OFFSET(FveApi, OFFSET_FVE_DATUM_NESTED_GET_NEXT, FveDatumNestedGetNext);
	DYNAMIC_LINK_OFFSET(FveApi, OFFSET_FVE_DATASET_APPEND_DATUM, FveDatasetAppendDatum);
	
	HANDLE hFve;
	HRESULT result = FveOpenVolumeW(argv[1], true, &hFve);
	if (FAILED(result)) { printf("FveOpenVolumeW() failed %x", result); return 0; }
	void* pFve = (void*)((size_t)hFve ^ HANDLE_KEY);
	PFVE_DATASET Dataset = *(PFVE_DATASET*) POINTER_FROM_OFFSET(pFve, OFFSET_DATASET);
	
	// For each VMK:
	DWORD vmkCount = 0;
	DWORD alreadyVmkCount = 0;
	for (DWORD offVmkInfo = 0; NT_SUCCESS(FveDatasetGetNext(Dataset, 2, 8, offVmkInfo, &offVmkInfo)); ) {
		PFVE_DATUM_VMK_INFO VmkInfo;
		if (!NT_SUCCESS(FveDatasetGetDatumPointer(Dataset, offVmkInfo, (PPFVE_DATUM)&VmkInfo))) goto done;
		// Is this a plain-text VMK? If not, skip.
		printf("VMK: crypto type == %d\n", VmkInfo->Priority >> 8);
		if ((VmkInfo->Priority >> 8) != 0) continue;
		// For each key blob in the VMK:
		for (WORD offVmkKey = 0; NT_SUCCESS(FveDatumNestedGetNext(&VmkInfo->h, 0xFFFF, 0xFFFF, offVmkKey, &offVmkKey)); ) {
			PFVE_DATUM_KEY VmkKey;
			if (!NT_SUCCESS(FveDatasetGetDatumPointer(Dataset, offVmkInfo + offVmkKey, (PPFVE_DATUM)&VmkKey))) continue;
			// expected type key...
			printf("VMKkey: type = %d\n", VmkKey->h.Type);
			if (VmkKey->h.Type != 1) continue;
			// if the flag is already set, don't bother.
			if ((VmkKey->KeyFlags & 1) == 1) { alreadyVmkCount++; continue; }
			VmkKey->KeyFlags |= 1;
			vmkCount++;
		}
	}
	if (vmkCount == 0) {
		printf("Key flag was already set in %d VMK key%s\n", alreadyVmkCount, alreadyVmkCount != 1 ? "s" : "");
		if (alreadyVmkCount == 0) goto done;
	} else {
		printf("Set key flag in %d VMK key%s!\n", vmkCount, vmkCount != 1 ? "s" : "");
	}

	// If secure boot validation info already inside the metadata, no need to do that.
	DWORD offValidation = 0;
	if (!NT_SUCCESS(FveDatasetGetNext(Dataset, 4, 7, 0, &offValidation))) {
		FVE_DATUM Metadata;
		Metadata.StructureSize = sizeof(FVE_DATUM);
		Metadata.Role = 4;
		Metadata.Type = 7;
		Metadata.Flags = 0;
		if (NT_SUCCESS(FveDatasetAppendDatum(Dataset, &Metadata, 4))) {
			printf("Added secure boot validation info!\n");
		}
	} else {
		printf("Secure boot validation info was already added!\n");
		goto done;
	}
	
	result = FveCommitChanges(hFve);
	if (FAILED(result)) printf("FveCommitChanges failed %x\n", result);
	done:
	result = FveCloseVolume(hFve);
	if (FAILED(result)) printf("FveCloseVolume failed %x\n", result);
}