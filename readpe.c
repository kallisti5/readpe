/*
 * Copyright 2014 Alexander von Gluck IV
 * Released under the terms of the MIT license
 */

// Like readelf, but for PE binaries

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

typedef uint8_t uint8;
typedef uint16_t uint16;
typedef uint32_t uint32;

struct MzHeader {
	uint16 magic; /* == 0x5a4D */
	uint16 bytesInLastBlock;
	uint16 blocksInFile;
	uint16 numRelocations;
	uint16 headerParagraphs;
	uint16 minExtraParagraphs;
	uint16 maxExtraParagraphs;
	uint16 ss;
	uint16 sp;
	uint16 checksum;
	uint16 ip;
	uint16 cs;
	uint16 relocationTableOffset;
	uint16 overlayNumber;
	uint16 reserved[4];
	uint16 oemID;
	uint16 oemInfo;
	uint16 reserved2[10];
	uint32 lfaNew;	// PE Address
};

struct PeHeader {
	uint32 magic; // 0x4550
	uint16 machine;
	uint16 numberOfSections;
	uint32 timeDateStamp;
	uint32 pointerToSymbolTable;
	uint32 numberOfSymbols;
	uint16 sizeOfOptionalHeader;
	uint16 characteristics;
};

struct Pe32OptionalHeader {
	uint16 magic; // 0x010b - PE32, 0x020b - PE32+ (64 bit)
	uint8  majorLinkerVersion;
	uint8  minorLinkerVersion;
	uint32 sizeOfCode;
	uint32 sizeOfInitializedData;
	uint32 sizeOfUninitializedData;
	uint32 addressOfEntryPoint;
	uint32 baseOfCode;
	uint32 baseOfData;
	uint32 imageBase;
	uint32 sectionAlignment;
	uint32 fileAlignment;
	uint16 majorOperatingSystemVersion;
	uint16 minorOperatingSystemVersion;
	uint16 majorImageVersion;
	uint16 minorImageVersion;
	uint16 majorSubsystemVersion;
	uint16 minorSubsystemVersion;
	uint32 win32VersionValue;
	uint32 sizeOfImage;
	uint32 sizeOfHeaders;
	uint32 checksum;
	uint16 subsystem;
	uint16 llCharacteristics;
	uint32 sizeOfStackReserve;
	uint32 sizeOfStackCommit;
	uint32 sizeOfHeapReserve;
	uint32 sizeOfHeapCommit;
	uint32 loaderFlags;
	uint32 numberOfRvaAndSizes;
};


int
main(int argc, char* argv[])
{
	if (argc != 2) {
		printf("Usage: readpe <PE Binary>\n");
		exit(1);
	}

	FILE * fd = fopen(argv[1], "rb");
	if (fd==NULL) {
		fputs("File error!\n", stderr);
		exit(1);
	}
	// Determine file size
	fseek(fd, 0, SEEK_END);
	off_t size = ftell(fd);
	rewind(fd);

	// Allocate memory for it and read file into memory
	void* buffer = malloc(size + 1);
	fread(buffer, size, 1, fd);
	fclose(fd);

	// First we load the DOS MZ Stub header...
	struct MzHeader* mz = malloc(sizeof(struct MzHeader));
	memcpy(mz, buffer, sizeof(struct MzHeader));

	printf("MZ (dos) header:\n");
	printf("  magic: %X\n", mz->magic);
	printf("  bytesInLastBlock: %X\n", mz->bytesInLastBlock);
	printf("  blocksInFile: %X\n", mz->blocksInFile);
	printf("  numRelocations: %X\n", mz->numRelocations);
	printf("  headerParagraphs: %X\n", mz->headerParagraphs);
	printf("  minExtraParagraphs: %X\n", mz->minExtraParagraphs);
	printf("  maxExtraParagraphs: %X\n", mz->maxExtraParagraphs);
	printf("  ss: %X\n", mz->ss);
	printf("  sp: %X\n", mz->sp);
	printf("  checksum: %X\n", mz->checksum);
	printf("  ip: %X\n", mz->ip);
	printf("  cs: %X\n", mz->cs);
	printf("  relocationTableOffset: %X\n", mz->relocationTableOffset);
	printf("  overlayNumber: %X\n", mz->overlayNumber);
	printf("  reserved[4]: -\n");
	printf("  oemID: %X\n", mz->oemID);
	printf("  oemInfo: %X\n", mz->oemInfo);
	printf("  reserved2[10]: -\n");
	printf("  lfaNew: %X\n", mz->lfaNew);

	// Access the PE header provided by lfaNew...
	struct PeHeader* pe = malloc(sizeof(struct PeHeader));
	memcpy(pe, buffer + mz->lfaNew, sizeof(struct PeHeader));
	printf("PE header:\n");
	printf("  magic: %X\n", pe->magic);
	printf("  machine: %X\n", pe->machine);
	printf("  numberOfSections: %X\n", pe->numberOfSections);
	printf("  timeDateStamp: %X\n", pe->timeDateStamp);
	printf("  pointerToSymbolTable: %X\n", pe->pointerToSymbolTable);
	printf("  numberOfSymbols: %X\n", pe->numberOfSymbols);
	printf("  sizeOfOptionalHeader: %X\n", pe->sizeOfOptionalHeader);
	printf("  characteristics: %X\n", pe->characteristics);

	if (pe->sizeOfOptionalHeader > 0) {
		struct Pe32OptionalHeader* peOpt
			= malloc(sizeof(struct Pe32OptionalHeader));
		memcpy(peOpt, buffer + mz->lfaNew + sizeof(struct PeHeader),
			sizeof(struct Pe32OptionalHeader));
		printf("PE optional header: (present)\n");
		printf("  magic: %X\n", peOpt->magic);
		// ...
		printf("  majorOperatingSystemVersion: %X\n",
			peOpt->majorOperatingSystemVersion);
		printf("  minorOperatingSystemVersion: %X\n",
			peOpt->minorOperatingSystemVersion);
		printf("  majorImageVersion: %X\n", peOpt->majorImageVersion);
		printf("  minorImageVersion: %X\n", peOpt->minorImageVersion);
		printf("  majorSubsystemVersion: %X\n", peOpt->majorSubsystemVersion);
		printf("  minorSubsystemVersion: %X\n", peOpt->minorSubsystemVersion);
		// ...
		free(peOpt);
	} else {
		printf("PE optional header: (none)\n");
	}

	free(buffer);
	free(mz);
	free(pe);
}
