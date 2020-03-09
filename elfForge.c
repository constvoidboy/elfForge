#include <stdlib.h>
#include <stdio.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

struct elf32 {
	Elf32_Ehdr *ehdr;
};

struct elf64 {
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;
};

void handler32(struct elf32 *, void *);
void handler64(struct elf64 *, void *);

int main(int argc, char **argv)
{
	int fd, arch;
	struct stat stat;
	struct elf32 e32;
	struct elf64 e64;
	void *p;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <elf>\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	if ((fd = open(argv[1], O_RDONLY)) == -1) {
		fprintf(stderr, "[!] - open %s failed with %s\n", argv[1], strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (fstat(fd, &stat) == -1) {
		fprintf(stderr, "[!] - fstat failed with %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	if ((p = mmap(NULL, stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) == (void *)-1) {
		close(fd);
		fprintf(stderr, "[!] - mmap failed with %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	/* file is now mapped in memory, we can close it */
	close(fd);
	/* Verify magic number and 'ELF' pattern */
	if (memcmp(p, "\x7f\x45\x4C\x46", 4) != 0) {
		fprintf(stderr, "[!] - %s is not an ELF file\n", argv[1]);
		exit(EXIT_FAILURE);
	}	
	/* EI_CLASS - architecture */
	switch(((unsigned char *)p)[4]) {
		case ELFCLASSNONE:
			fprintf(stdout, "[?] - Invalid ELF class\n");
			break;
		case ELFCLASS32:
			fprintf(stdout, "[*] -  32-bit ELF\n");
			e32.ehdr = (Elf32_Ehdr *)p;
			arch = 32;
			break;
		case ELFCLASS64:
			fprintf(stdout, "[*] - 64-bit ELF\n");
			e64.ehdr = (Elf64_Ehdr *)p;
			arch = 64;
			break;
		default:
			/* if unknow architecture, try 64-bit */
			fprintf(stdout, "[!] - Unknow ELF class\n");
			e64.ehdr = (Elf64_Ehdr *)p;
			arch = -1;
	}
	/* 
	 * Elf32_Ehdr and Elf64_Ehdr are identical except 
	 * entry point, e_entry which is ElfN_Addr
	 * p. h. offst, e_phoff which is ElfN_Off
	 * s. h. offst, e_shoff which is ElfN_Off
	 */
	switch(((unsigned char *)p)[5]) {
		case ELFDATANONE:
			fprintf(stdout, "[?] - Unknow data format\n");
			break;
		case ELFDATA2LSB:
			fprintf(stdout, "[*] - Two's complement, little-endian\n");
			break;
		case ELFDATA2MSB:
			fprintf(stdout, "[*] - Two's complement, big-endian\n");
			break;
		default:
			fprintf(stdout, "[!] - Invalid data encoding\n");
	}
	switch(((unsigned char *)p)[6]) {
		case EV_NONE:
			fprintf(stdout, "[?] - Invalid version\n");
			break;
		case EV_CURRENT:
			fprintf(stdout, "[*] - Current version: 0x%x\n", EV_CURRENT);
			break;
		default:
			fprintf(stdout, "[!] - Unknow version\n");
	}
	switch(((unsigned char *)p)[7]) {
		case ELFOSABI_SYSV:
			fprintf(stdout, "[*] - UNIX System V ABI\n");
			break;
		case ELFOSABI_HPUX:
			fprintf(stdout, "[*] - HP-UX ABI\n");
			break;
		case ELFOSABI_NETBSD:
			fprintf(stdout, "[*] - NetBSD ABI\n");
			break;
		case ELFOSABI_LINUX:
			fprintf(stdout, "[*] - Linux ABI\n");
			break;
		case ELFOSABI_SOLARIS:
			fprintf(stdout, "[*] - Solaris ABI\n");
			break;
		case ELFOSABI_IRIX:
			fprintf(stdout, "[*] - IRIX ABI\n");
			break;
		case ELFOSABI_FREEBSD:
			fprintf(stdout, "[*] - FreeBSD ABI\n");
			break;
		case ELFOSABI_TRU64:
			fprintf(stdout, "[*] - TRU64 UNIX ABI\n");
			break;
		case ELFOSABI_ARM:
			fprintf(stdout, "[*] - ARM architecture ABI\n");
			break;
		case ELFOSABI_STANDALONE:
			fprintf(stdout, "[*] - Stand-alone (embedded) ABI\n");
			break;
		default:
			fprintf(stdout, "[!] - Unknow ABI version\n");
	}
	fprintf(stdout, "[*] - ABI version : %u\n", ((unsigned char *)p)[8]);
	/* EI_PAD and EI_NIDENT are ignored */
	switch(arch) {
		case 32:
			handler32(&e32, p);
			break;
		case 64:
			handler64(&e64, p);
			break;
		default:
			handler64(&e64, p);
	}
	/* ensure file is unmapped from memory */
	munmap(p, stat.st_size);

	return 0;
}

void handler32(struct elf32 *elf, void *p)
{
	/* TODO */
	switch(elf->ehdr->e_type) {
		case ET_NONE:
			break;
		case ET_REL:
			break;
		case ET_EXEC:
			break;
		case ET_DYN:
			break;
		case ET_CORE:
			break;
		default:
			fprintf(stdout, "[!] - Invalid file type\n");
	}


}

void handler64(struct elf64 *elf, void *p)
{
	unsigned long sectionCount, programCount, i, j;
	char *stringTable;
	char *symbolTable;
	Elf64_Dyn *dyn = NULL;
	Elf64_Sym *sym = NULL;

	switch(elf->ehdr->e_type) {
		case ET_NONE:
			fprintf(stdout, "[?] - Unknow type\n");
			break;
		case ET_REL:
			fprintf(stdout, "[*] - Relocatable file\n");
			break;
		case ET_EXEC:
			fprintf(stdout, "[*] - Executable file\n");
			break;
		case ET_DYN:
			fprintf(stdout, "[*] - Shared object\n");
			break;
		case ET_CORE:
			fprintf(stdout, "[*] - Core file\n");
			break;
		default:
			fprintf(stdout, "[!] - Invalid file type\n");
	}
	switch(elf->ehdr->e_machine) {
		/* TODO: implements all cases */
		case EM_NONE:
			fprintf(stdout, "[?] - Unknow machine\n");
			break;
		case EM_X86_64:
			fprintf(stdout, "[*] - AMD x86-64\n");
			break;
		case EM_386:
			fprintf(stdout, "[*] - Intel 80386\n");
			break;
		case EM_ARM:
			fprintf(stdout, "[*] - Advanced RISC Machines\n");
			break;
	}
	switch(elf->ehdr->e_version) {
		case EV_NONE:
			fprintf(stdout, "[?] - Invalid version\n");
			break;
		case EV_CURRENT:
			fprintf(stdout, "[*] - Current version: 0x%x\n", EV_CURRENT);
			break;
		default:
			fprintf(stdout, "[!] - Unknow version\n");
	}
	fprintf(stdout, "[*] - Entry point : 0x%lx\n", elf->ehdr->e_entry);
	/* Set program header */
	elf->phdr = (Elf64_Phdr *)((unsigned char *)p + elf->ehdr->e_phoff);
	fprintf(stdout, "[*] - Program header offset : 0x%lx\n", elf->ehdr->e_phoff);
	/* Set section header */
	elf->shdr = (Elf64_Shdr *)((unsigned char *)p + elf->ehdr->e_shoff);
	fprintf(stdout, "[*] - Section header offset : 0x%lx\n", elf->ehdr->e_shoff);
	/* e_flags is not defined yet, just ignore it */
	fprintf(stdout, "[*] - ELF header's size: 0x%x bytes\n", elf->ehdr->e_ehsize);
	/* Program header Méta */
	fprintf(stdout, "[*] - ELF program header's size: 0x%x bytes\n", elf->ehdr->e_phentsize);
	if (elf->ehdr->e_phnum >= PN_XNUM) 
		programCount = elf->shdr->sh_info;
	else 
		programCount = elf->ehdr->e_phnum;
	fprintf(stdout, "[*] - ELF program header count: %ld\n", programCount);
	/* Section header Méta */
	fprintf(stdout, "[*] - ELF section header's size: 0x%x bytes\n", elf->ehdr->e_shentsize);
	if (elf->ehdr->e_phnum >= SHN_LORESERVE) 
		sectionCount = elf->shdr->sh_size;
	else
		sectionCount = elf->ehdr->e_shnum;
	fprintf(stdout, "[*] - ELF section header count: %ld\n", sectionCount);
	/* String table */
	if (elf->ehdr->e_shstrndx == SHN_UNDEF) {
		fprintf(stdout, "[*] - No section name string table\n");
		stringTable = NULL;
	} else if (elf->ehdr->e_shstrndx >= SHN_LORESERVE) {
		fprintf(stdout, "[*] - Index of section name string table: %d\n", elf->shdr->sh_link);
		stringTable = (char *)p + elf->shdr[elf->shdr->sh_link].sh_offset;
	} else {
		fprintf(stdout, "[*] - Index of section name string table: %d\n", elf->ehdr->e_shstrndx);
		stringTable = (char *)p + elf->shdr[elf->ehdr->e_shstrndx].sh_offset;
	}
	/* Iterate Program Headers entries */
	fprintf(stdout,"------ Program headers ------\n");
	for (i = 0; i < programCount; i++) {
		fprintf(stdout,"[%d]", i);
		/* TODO: implements others p_type */
		switch(elf->phdr[i].p_type) {
			case PT_NULL:
				fprintf(stdout, "%10s", "NULL");
				break;
			case PT_LOAD:
				fprintf(stdout, "%10s", "LOAD");
				break;
			case PT_DYNAMIC:
				dyn = (Elf64_Dyn *)((unsigned char *)p + elf->phdr[i].p_offset);
				fprintf(stdout, "%10s", "DYNAMIC");
				break;
			case PT_INTERP:
				fprintf(stdout, "%10s \t%s\n", "INTERP", (unsigned char *)p + elf->phdr[i].p_offset);
				continue;
			case PT_NOTE:
				fprintf(stdout, "%10s", "NOTE");
				break;
			case PT_SHLIB:
				fprintf(stdout, "%10s", "SHLIB");
				break;
			case PT_PHDR:
				fprintf(stdout, "%10s", "PHDR");
				break;
			case PT_LOPROC:
				fprintf(stdout, "%10s", "LOPROC");
				break;
			case PT_HIPROC:
				fprintf(stdout, "%10s", "HIPROC");
				break;
			case PT_GNU_STACK:
				fprintf(stdout, "%10s", "GNU_STACK");
				break;
			default:
				fprintf(stdout, "%10s", "Unknown");
		}
		fprintf(stdout, " %4s | %4s | %4s", elf->phdr[i].p_flags & PF_R ? "READ" : "-",
						elf->phdr[i].p_flags & PF_W ? "WRIT" : "-",
						elf->phdr[i].p_flags & PF_X ? "EXEC" : "-");
		fprintf(stdout," 0x%lx", elf->phdr[i].p_offset);
		fprintf(stdout," 0x%lx", elf->phdr[i].p_vaddr);
		fprintf(stdout," 0x%lx", elf->phdr[i].p_paddr);
		fprintf(stdout," 0x%lx", elf->phdr[i].p_filesz);
		fprintf(stdout," 0x%lx", elf->phdr[i].p_memsz);
		fprintf(stdout," 0x%lx\n", elf->phdr[i].p_align);
	}
	/* Iterate Section Headers entries */
	fprintf(stdout,"------ Section headers ------\n");
	/* Skip [0], it is a reserved entry for ELF extensions */
	for (i = 1; i < sectionCount; i++) {
		if (i >= SHN_LORESERVE && i <= SHN_HIRESERVE)
			continue;
		fprintf(stdout,"[*] - Header n°%ld:\n", i);
		fprintf(stdout,"\tName: %s\n", stringTable + elf->shdr[i].sh_name);
		fprintf(stdout,"\tType: ");
		switch(elf->shdr[i].sh_type) {
			case SHT_NULL:
				fprintf(stdout, "NULL\n");
				break;
			case SHT_PROGBITS:
				fprintf(stdout, "PROGBITS\n");
				break;
			case SHT_SYMTAB:
				sym = (Elf64_Sym *)((char *)p + elf->shdr[i].sh_offset);
				symbolTable = (char *)p + elf->shdr[elf->shdr[i].sh_link].sh_offset;
				fprintf(stdout, "SYMTAB\n");
				for(j = 0; j < elf->shdr[i].sh_size/elf->shdr[i].sh_entsize; j++) {
					if (ELF64_ST_TYPE(sym[j].st_info) == STT_SECTION) 
						continue;
					fprintf(stdout, "\t%8lx", sym[j].st_value);
					fprintf(stdout, " %4ld", sym[j].st_size);
					/* TODO: implements all others st_info */
					switch(ELF64_ST_TYPE(sym[j].st_info)) {
						case STT_OBJECT:
							fprintf(stdout, "%10s" , "object");
							break;
						case STT_FUNC:
							fprintf(stdout, "%10s" , "function");
							break;
						case STT_SECTION:
							fprintf(stdout, "%10s" , "section");
							break;
						case STT_FILE:
							fprintf(stdout, "%10s" , "file");
							break;
						case STB_LOCAL:
							fprintf(stdout, "%10s" , "local");
							break;
						default:
							fprintf(stdout, "%10s" , "invalid");
							break;
					}
					switch(ELF64_ST_VISIBILITY(sym[j].st_other)) {
						case STV_DEFAULT:
							fprintf(stdout, "%10s", "DEAULT");
							break;
						case STV_INTERNAL:
							fprintf(stdout, "%10s", "INTERNAL");
							break;
						case STV_HIDDEN:
							fprintf(stdout, "%10s", "HIDDEN");
							break;
						case STV_PROTECTED:
							fprintf(stdout, "%10s", "PROTECTED");
							break;
					}
					fprintf(stdout, " %5d", sym[j].st_shndx);
					fprintf(stdout, " %10s\n", symbolTable + sym[j].st_name);
				}
				break;
			case SHT_STRTAB:
				fprintf(stdout, "STRTAB\n");
				break;
			case SHT_RELA:
				fprintf(stdout, "RELA\n");
				break;
			case SHT_HASH:
				fprintf(stdout, "HASH\n");
				break;
			case SHT_DYNAMIC:
				fprintf(stdout, "DYNAMIC\n");
				break;
			case SHT_NOTE:
				fprintf(stdout, "NOTE\n");
				break;
			case SHT_NOBITS:
				fprintf(stdout, "NOBITS\n");
				break;
			case SHT_REL:
				fprintf(stdout, "REL\n");
				break;
			case SHT_SHLIB:
				fprintf(stdout, "SHLIB\n");
				break;
			case SHT_DYNSYM:
				fprintf(stdout, "DYNSYM\n");
				break;
			case SHT_LOPROC:
				fprintf(stdout, "LOPROC\n");
				break;
			case SHT_HIPROC:
				fprintf(stdout, "HIPROC\n");
				break;
			case SHT_LOUSER:
				fprintf(stdout, "LOUSER\n");
				break;
			case SHT_HIUSER:
				fprintf(stdout, "HIUSER\n");
				break;
			default:
				fprintf(stdout, "Unknown type\n");
		}
		fprintf(stdout,"\tOffset: %lx\n", elf->shdr[i].sh_offset);
		fprintf(stdout,"\tFlags: %s | %s | %s | %s\n", elf->shdr[i].sh_flags & SHF_WRITE ? "WRITE" : "-",
								elf->shdr[i].sh_flags & SHF_ALLOC ? "ALLOC " : "-",
								elf->shdr[i].sh_flags & SHF_EXECINSTR ? "EXECINST" : "-",
								elf->shdr[i].sh_flags & SHF_MASKPROC ? "MASKPROC" : "-");
		fprintf(stdout,"\tAddr: %lx\n", elf->shdr[i].sh_addr);
		fprintf(stdout,"\tSize: %ld\n", elf->shdr[i].sh_size);
		fprintf(stdout,"\tLink: %d\n", elf->shdr[i].sh_link);
		fprintf(stdout,"\tInfo: %x\n", elf->shdr[i].sh_info);
		fprintf(stdout,"\tAlign: %lx\n", elf->shdr[i].sh_addralign);
		fprintf(stdout,"\tTable's entry Size: %ld\n", elf->shdr[i].sh_entsize);
	}
}
