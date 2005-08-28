#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

typedef struct _IMAGE_DOS_HEADER {
	unsigned short int e_magic;
	unsigned short int e_cblp;
	unsigned short int e_cp;
	unsigned short int e_crlc;
	unsigned short int e_cparhdr;
	unsigned short int e_minalloc;
	unsigned short int e_maxalloc;
	unsigned short int e_ss;
	unsigned short int e_sp;
	unsigned short int e_csum;
	unsigned short int e_ip;
	unsigned short int e_cs;
	unsigned short int e_lfarlc;
	unsigned short int e_ovno;
	unsigned short int e_res[4];
	unsigned short int e_oemid;
	unsigned short int e_oeminfo;
	unsigned short int e_res2[10];
	unsigned int e_lfanew;
} IMAGE_DOS_HEADER,*PIMAGE_DOS_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
	unsigned int VirtualAddress;
	unsigned int Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_FILE_HEADER {
	unsigned short int Machine;
	unsigned short int NumberOfSections;
	unsigned int TimeDateStamp;
	unsigned int PointerToSymbolTable;
	unsigned int NumberOfSymbols;
	unsigned short int SizeOfOptionalHeader;
	unsigned short int Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER {
	unsigned short int Magic;
	char MajorLinkerVersion;
	char MinorLinkerVersion;
	unsigned int SizeOfCode;
	unsigned int SizeOfInitializedData;
	unsigned int SizeOfUninitializedData;
	unsigned int AddressOfEntryPoint;
	unsigned int BaseOfCode;
	unsigned int BaseOfData;
	unsigned int ImageBase;
	unsigned int SectionAlignment;
	unsigned int FileAlignment;
	unsigned short int MajorOperatingSystemVersion;
	unsigned short int MinorOperatingSystemVersion;
	unsigned short int MajorImageVersion;
	unsigned short int MinorImageVersion;
	unsigned short int MajorSubsystemVersion;
	unsigned short int MinorSubsystemVersion;
	unsigned int Reserved1;
	unsigned int SizeOfImage;
	unsigned int SizeOfHeaders;
	unsigned int CheckSum;
	unsigned short int Subsystem;
	unsigned short int DllCharacteristics;
	unsigned int SizeOfStackReserve;
	unsigned int SizeOfStackCommit;
	unsigned int SizeOfHeapReserve;
	unsigned int SizeOfHeapCommit;
	unsigned int LoaderFlags;
	unsigned int NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;



typedef struct _IMAGE_NT_HEADERS {
	unsigned int Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER OptionalHeader;
} IMAGE_NT_HEADERS;
