rule HKTL_NimGetSyscallStub : EXE FILE HKTL
{
    meta:
        description = "Detects binaries using NimGetSyscallStub for shellcode injection"
        author = "Fabian Mosch (@Shitsecure), parts shamelessly copied from @chvancooten's NimPackt-v1 rule"
        reference = "https://github.com/S3cur3Th1sSh1t/NimGetSyscallStub"
        date = "2022-01-28"
        
    strings:
        $nim1 = "fatal.nim" ascii fullword
        $nim2 = "winim" ascii
        $sus = { 40 43 3A 5C 77 69 6E 64 6F 77 73 5C 73 79 73 74 65 6D 33 32 5C 6E 74 64 6C 6C 2E 64 6C 6C }
        $sus2 = { 46 6F 75 6E 64 20 53 79 73 63 61 6C 6C 20 53 54 55 42 21 }

    condition:
        uint16(0) == 0x5A4D and
        filesize < 750KB and
        1 of ($nim*) and (
            $sus and $sus2
        )
}