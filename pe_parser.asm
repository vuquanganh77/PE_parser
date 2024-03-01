.386
option casemap:none

include \masm32\include\masm32rt.inc

.data
    ;fileName db "D:\\masm32\\reverse_string.exe", 0
    fileName db "C:\\Windows\\System32\\amdtee_api.dll", 0
    ;fileName db 256 DUP (0)
    bytesRead DWORD ?
    string_hex db 4 DUP (0)  ;data chuyển từ hex sang ascii
    string_decimal db 16 DUP (0)
    string_decimal1 db 16 DUP (0)
    Buffer db 100000 dup(?)

    hConsoleOut DWORD ?
    buffer db 4096 dup(0)
    prompt db "Enter file path ",0

    dosHeader db  "***** DOS Headers *****",0
    eMagic db "e_magic",9,9,9,9,9,"0x",0                       ; 0 la ascii cua ki tu ket thuc, 9 la ascii cua ki tu \t
    eCblp db "e_cblp",9,9,9,9,9,"0x",0
    eCp db "e_cp",9,9,9,9,9,"0x",0
    eCrlc db "e_crlc",9,9,9,9,9,"0x",0
    eCparhdr db "e_cparhdr",9,9,9,9,"0x",0
    eMinalloc db "e_minalloc",9,9,9,9,"0x",0
    eMaxalloc db "e_maxalloc",9,9,9,9,"0x",0
    eSs db "e_ss",9,9,9,9,9,"0x",0
    e_Sp db "e_sp",9,9,9,9,9,"0x",0
    eCsum db "e_csum",9,9,9,9,9,"0x",0
    e_Ip db "e_ip",9,9,9,9,9,"0x",0
    eCs db "e_cs",9,9,9,9,9,"0x",0
    eLfarlc db "e_lfarlc",9,9,9,9,"0x",0
    eOvno db "e_ovno",9,9,9,9,9,"0x",0
    eRes db "e_res",9,9,9,9,9,"0x",0
    eOemid db "e_oemid",9,9,9,9,9,"0x",0
    eOeminfo db "e_oeminfo",9,9,9,9,"0x",0
    eRes2 db "e_res2",9,9,9,9,9,"0x",0
    eLfanew db "e_lfanew",9,9,9,9,"0x",0

    ntHeaders db  "***** NT Headers *****",0
    signature DWORD ?
    signatures db "Signature",9,9,9,9,"0x",0

    fileHeaders db  "***** File Headers *****",0
    machine db "Machine",9,9,9,9,9,"0x",0
    numberOfSections db "NumberOfSections",9,9,9,"0x",0
    timeDateStamp db "TimeDateStamp",9,9,9,9,"0x",0 
    pointerToSymbolTable db "PointerToSymbolTable",9,9,9,"0x",0
    numberOfSymbols db "NumberOfSymbol",9,9,9,9,"0x",0
    sizeOfOptionalHeaders db "SizeOfOptionalHeader",9,9,9,"0x",0
    characteristics db "Characteristics",9,9,9,9,"0x",0

    optionalHeader db "***** Optional Headers *****",0
    magic db "Magic",9,9,9,9,9,"0x",0
    majorLinkerVersion db "MajorLinkerVersion",9,9,9,"0x",0
    minorLinkerVersion db "MinorLinkerVersion",9,9,9,"0x",0
    sizeOfCode db "SizeOfCode",9,9,9,9,"0x",0
    sizeOfInitializedData db "SizeOfInitializedData",9,9,9,"0x",0
    sizeOfUninitializedData db "SizeOfUninitializedData",9,9,9,"0x",0
    addressOfEntryPoint db "AddressOfEntryPoint",9,9,9,"0x",0
    baseOfCode db "BaseOfCode",9,9,9,9,"0x",0
    baseOfData db "BaseOfData",9,9,9,9,"0x",0
    imageBase db "ImageBase",9,9,9,9,"0x",0
    sectionAlignment db "SectionAlignment",9,9,9,"0x",0
    fileAlignment db "FileAlignment",9,9,9,9,"0x",0
    majorOperatingSystemVersion db "MajorOperatingSystemVersion",9,9,"0x",0
    minorOperatingSystemVersion db "MinorOperatingSystemVersion",9,9,"0x",0
    majorImageVersion db "MajorImageVersion",9,9,9,"0x",0
    minorImageVersion db "MinorImageVersion",9,9,9,"0x",0
    majorSubsystemVersion db "MajorSubsystemVersion",9,9,9,"0x",0
    minorSubsystemVersion db "MinorSubsystemVersion",9,9,9,"0x",0
    win32version db "Win32VersionValue",9,9,9,"0x",0
    sizeOfImage db "SizeOfImage",9,9,9,9,"0x",0
    sizeOfHeader db "SizeOfHeader",9,9,9,9,"0x",0
    checksum db "CheckSum",9,9,9,9,"0x",0
    subsystem db "Subsystem",9,9,9,9,"0x",0
    dllCharacteristics db "DllCharacteristics",9,9,9,"0x",0
    sizeOfStackReserve db "SizeOfStackReserve",9,9,9,"0x",0
    sizeOfStackCommit db "SizeOfStackCommit",9,9,9,"0x",0
    sizeOfHeapReserve db "SizeOfHeapReserve",9,9,9,"0x",0
    sizeOfHeapCommit db "SizeOfHeapCommit",9,9,9,"0x",0
    loaderFlag db "LoaderFlags",9,9,9,9,"0x",0
    numberOfRvaAndSizes db "NumberOfRvaAndSizes",9,9,9,"0x",0

    dataDirectory db "***** Data Directories *****",0
    exportDirectoryRVA db "Export Directory RVA",9,9,9,"0x",0
    exportDirectorySize db "Export Directory Size",9,9,9,"0x",0
    importDirectoryRVA db "Import Directory RVA",9,9,9,"0x",0
    importDirectorySize db "Export Directory Size",9,9,9,"0x",0
    resourceDirectoryRVA db "Resource Directory RVA",9,9,9,"0x",0
    resourceDirectorySize db "Resource Directory Size",9,9,9,"0x",0
    exceptionDirectoryRVA db "Exception Directory RVA",9,9,9,"0x",0
    exceptionDirectorySize db "Exception Directory Size",9,9,"0x",0
    securityDirectoryRVA db "Security Directory RVA",9,9,9,"0x",0
    securityDirectorySize db "Security Directory Size",9,9,9,"0x",0
    relocationDirectoryRVA db "Relocation Directory RVA",9,9,"0x",0
    relocationDirectorySize db "Relocation Directory Size",9,9,"0x",0
    debugDirectoryRVA db "Debug Directory RVA",9,9,9,"0x",0
    debugDirectorySize db "Debug Directory Size",9,9,9,"0x",0
    architectureDirectoryRVA db "Architecture Directory RVA",9,9,"0x",0
    architectureDirectorySize db "Architecture Directory Size",9,9,"0x",0
    reserved db "Reserved",9,9,9,9,"0x",0
    tlsDirectoryRVA db "TLS Directory RVA",9,9,9,"0x",0
    tlsDirectorySize db "TLS Directory Size",9,9,9,"0x",0
    configurationDirectoryRVA db "Configuration Directory RVA",9,9,"0x",0
    configurationDirectorySize db "Configuration Directory Size",9,9,"0x",0
    boundImportDirectoryRVA db "Bound Import Directory RVA",9,9,"0x",0
    boundImportDirectorySize db "Bound Import Directory Size",9,9,"0x",0
    importAddressTableDirectoryRVA db "Import Address Table Directory RVA",9,"0x",0
    importAddressTableDirectorySize db "Import Address Table Directory Size",9,"0x",0
    delayImportDirectoryRVA db "Delay Import Directory RVA",9,9,"0x",0
    delayImportDirectorySize db "Delay Import Directory Size",9,9,"0x",0
    netMetadataDirectoryRVA db ".NET Metadata Directory RVA",9,9,"0x",0
    netMetadataDirectorySize db ".NET Metadata Directory Size",9,9,"0x",0
    

    sectionHeader db "***** Section Headers *****",0
    size_of_optional_header DWORD ?
    ma_gic DWORD ?
    section DWORD ?
    number_of_section DWORD ?
    virtualSize db 9,"Virtual Size",9,9,9,"0x",0
    virtualAddress db 9,"Virtual Address",9,9,9,"0x",0
    sizeOfRawData db 9,"SizeOfRawData",9,9,9,"0x",0
    pointerToRawData db 9,"PointerToRawData",9,9,"0x",0
    pointerToRelocations db 9,"PointerToRelocations",9,9,"0x",0
    pointerToLineNumbers db 9,"PointerToLineNumbers",9,9,"0x",0
    numberOfRelocations db 9,"NumberOfRelocations",9,9,"0x",0
    numberOfLineNumbers db 9,"NumberOfLineNumbers",9,9,"0x",0
    characteristics1 db 9,"Characteristics",9,9,9,"0x",0

    dllImport db "***** DLL Imports *****",0
    importDirectoryRVA_ dword ?
    rDataRawAddress DWORD ?
    rDataVirtualAddress DWORD ?
    temp dword ?
    temp1 dword ?
    rdata_ db  2eh,72h,64h,61h,74h,61h,0
    check db  00h,00h
    check1 db  00h,00h,00h,00h
    importRVA dword ?       ;gia tri offset cua import list
    exportRVA dword ?       ;gia tri offset cua export list
    import_oft dword ?      ;OFTs
    importNameRVA dword ?   ;Name eva
    export_oft dword ?
    exportNameRVA dword ?
    import_lib dword ?      ; Gia tri cua oft
    import_lib_oft dword ?  ; Gia tri oft cua lib dau tien
    lib_name_offset dword ? ; Gia tri cua truong name RVA
    import_oft_offset dword ? ; Offset cua ofts

    ofts_column db "OFTS",0
    fts_column db "FTs",0
    name_column db "Name",0
    hex db "0x",0


    dllExport db "***** DLL Exports *****",0
    exportDirectoryRVA_ dword ?
    functionRVA dword ?
    export_name_rva_temp dword ?
    export_temp dword ?     ; Bien nay luu cac gia tri cua truong Name RVA trong bang export 
    export_name_offet dword ?   ; Bien nay luu gia tri offset cua export function name

    functionRVA_column db "Function RVA",0
    nameRVA_column db "Name RVA",0


    tab db 9,0
    newline db 13, 10, 0                                ;Ki hieu xuong dong
    importDescriptor DWORD  IMAGE_IMPORT_DESCRIPTOR 
    thunkData DWORD  IMAGE_THUNK_DATA 
    hFile DWORD HANDLE      

.code

print_value PROC adr :DWORD, number_of_bytes_read: DWORD 
    invoke SetFilePointer, hFile, adr, NULL, FILE_BEGIN
    invoke ReadFile, hFile, addr buffer, number_of_bytes_read, addr bytesRead, NULL
    mov eax, offset buffer
    mov eax, DWORD PTR [eax]
    mov edi, offset string_hex
    call to_hex_string
    invoke StdOut, offset string_hex
    ; Reset giá trị của chuỗi về rỗng
    ; mov eax, offset string_hex ; Con trỏ đến chuỗi
    ; mov ecx, sizeof string_hex ; Độ dài của chuỗi
    ; xor edx, edx ; Giá trị để gán (0)
    ; rep stosb ; Lặp qua từng byte và gán giá trị 0
    ret
print_value ENDP

print_ascii_value PROC adr :DWORD, number_of_bytes_read: DWORD 
    invoke SetFilePointer, hFile, adr, NULL, FILE_BEGIN
    invoke ReadFile, hFile, addr buffer, number_of_bytes_read, addr bytesRead, NULL
    invoke StdOut, offset buffer
    ret
print_ascii_value ENDP

save_value_of_import_oft PROC adr :DWORD, number_of_bytes_read: DWORD
    invoke SetFilePointer, hFile, adr, NULL, FILE_BEGIN
    invoke ReadFile, hFile, addr buffer, number_of_bytes_read, addr bytesRead, NULL

    ; 4 dòng sau chuyển từ giá trị ascii sang decimal
    mov eax, offset buffer
    mov eax, DWORD PTR [eax]
    mov edi, offset string_decimal
    call to_string
    ;invoke StdOut, offset string_decimal
    ;invoke StdOut,offset newline
    ; Chuyển từ string db sang số nguyên dword
    ; Load the address of source_string into esi
    lea esi, [string_decimal]
    ; Call atoi function to convert string to dword
    invoke atodw, esi
    mov import_oft, eax
    ret
save_value_of_import_oft ENDP

save_value_of_lib_name_offet PROC adr :DWORD, number_of_bytes_read: DWORD
    invoke SetFilePointer, hFile, adr, NULL, FILE_BEGIN
    invoke ReadFile, hFile, addr buffer, number_of_bytes_read, addr bytesRead, NULL

    ; 4 dòng sau chuyển từ giá trị ascii sang decimal
    mov eax, offset buffer
    mov eax, DWORD PTR [eax]
    mov edi, offset string_decimal
    call to_string
    ;invoke StdOut, offset string_decimal
    ;invoke StdOut,offset newline
    ; Chuyển từ string db sang số nguyên dword
    ; Load the address of source_string into esi
    lea esi, [string_decimal]
    ; Call atoi function to convert string to dword
    invoke atodw, esi
    mov lib_name_offset, eax
    ret
save_value_of_lib_name_offet ENDP

save_value_of_import_lib PROC adr :DWORD, number_of_bytes_read: DWORD
    invoke SetFilePointer, hFile, adr, NULL, FILE_BEGIN
    invoke ReadFile, hFile, addr buffer, number_of_bytes_read, addr bytesRead, NULL

    ; 4 dòng sau chuyển từ giá trị ascii sang decimal
    mov eax, offset buffer
    mov eax, DWORD PTR [eax]
    mov edi, offset string_decimal
    call to_string
    ;invoke StdOut, offset string_decimal
    ;invoke StdOut,offset newline
    ; Chuyển từ string db sang số nguyên dword
    ; Load the address of source_string into esi
    lea esi, [string_decimal]
    ; Call atoi function to convert string to dword
    invoke atodw, esi
    mov import_lib, eax
    ret
save_value_of_import_lib ENDP

save_value_of_export_name_rva PROC adr :DWORD, number_of_bytes_read: DWORD
    invoke SetFilePointer, hFile, adr, NULL, FILE_BEGIN
    invoke ReadFile, hFile, addr buffer, number_of_bytes_read, addr bytesRead, NULL

    ; 4 dòng sau chuyển từ giá trị ascii sang decimal
    mov eax, offset buffer
    mov eax, DWORD PTR [eax]
    mov edi, offset string_decimal
    call to_string
    ;invoke StdOut, offset string_decimal
    ;invoke StdOut,offset newline
    ; Chuyển từ string db sang số nguyên dword
    ; Load the address of source_string into esi
    lea esi, [string_decimal]
    ; Call atoi function to convert string to dword
    invoke atodw, esi
    mov export_temp, eax
    ret
save_value_of_export_name_rva ENDP


save_value_of_size_of_rdata_va PROC adr :DWORD, number_of_bytes_read: DWORD
    invoke SetFilePointer, hFile, adr, NULL, FILE_BEGIN
    invoke ReadFile, hFile, addr buffer, number_of_bytes_read, addr bytesRead, NULL

    ; 4 dòng sau chuyển từ giá trị ascii sang decimal
    mov eax, offset buffer
    mov eax, DWORD PTR [eax]
    mov edi, offset string_decimal
    call to_string
    ;invoke StdOut, offset string_decimal
    ;invoke StdOut,offset newline
    ; Chuyển từ string db sang số nguyên dword
    ; Load the address of source_string into esi
    lea esi, [string_decimal]
    ; Call atoi function to convert string to dword
    invoke atodw, esi
    mov rDataVirtualAddress, eax
    ret
save_value_of_size_of_rdata_va ENDP

save_value_of_size_of_rdata_raw_address PROC adr :DWORD, number_of_bytes_read: DWORD
    invoke SetFilePointer, hFile, adr, NULL, FILE_BEGIN
    invoke ReadFile, hFile, addr buffer, number_of_bytes_read, addr bytesRead, NULL

    ; 4 dòng sau chuyển từ giá trị ascii sang decimal
    mov eax, offset buffer
    mov eax, DWORD PTR [eax]
    mov edi, offset string_decimal
    call to_string
    ;invoke StdOut, offset string_decimal
    ;invoke StdOut,offset newline
    ; Chuyển từ string db sang số nguyên dword
    ; Load the address of source_string into esi
    lea esi, [string_decimal]
    ; Call atoi function to convert string to dword
    invoke atodw, esi
    mov rDataRawAddress, eax
    ret
save_value_of_size_of_rdata_raw_address ENDP

check_lib PROC adr :DWORD, number_of_bytes_read: DWORD
    invoke SetFilePointer, hFile, adr, NULL, FILE_BEGIN
    invoke ReadFile, hFile, addr buffer, number_of_bytes_read, addr bytesRead, NULL


    MOV ECX, LENGTHOF check ; Độ dài của chuỗi
    MOV ESI, OFFSET check   ; Con trỏ của chuỗi 1
    MOV EDI, OFFSET buffer   ; Con trỏ của chuỗi 2
    REPE CMPSB                 ; So sánh từng byte của hai chuỗi
    JZ strings_equal1         ; Nếu chuỗi giống nhau, nhảy tới nhãn strings_equal1

    strings_not_equal1:
        add eax,2
        invoke print_ascii_value,eax,10

    strings_equal1:
    ret
check_lib ENDP

; In va kiem tra gia tri ascii co = .rdata khong
print_and_check_ascii_value PROC adr :DWORD, number_of_bytes_read: DWORD 
    invoke SetFilePointer, hFile, adr, NULL, FILE_BEGIN
    invoke ReadFile, hFile, addr buffer, number_of_bytes_read, addr bytesRead, NULL

    MOV ECX, LENGTHOF rdata_ ; Độ dài của chuỗi
    MOV ESI, OFFSET rdata_   ; Con trỏ của chuỗi 1
    MOV EDI, OFFSET buffer   ; Con trỏ của chuỗi 2
    REPE CMPSB                 ; So sánh từng byte của hai chuỗi
    JZ strings_equal           ; Nếu chuỗi giống nhau, nhảy tới nhãn strings_equal

strings_not_equal:
    ;invoke StdOut, offset buffer
    JMP done

strings_equal:
    ; Chuỗi giống nhau
    ;mov eax,adr
    invoke StdOut, offset buffer
    mov eax, adr
    mov temp,eax
    add temp,12
    ;invoke print_value,temp,4
    invoke save_value_of_size_of_rdata_va,temp,4
    add temp,8
    ;invoke print_value,temp,4
    invoke save_value_of_size_of_rdata_raw_address,temp,4
done:
    invoke StdOut, offset buffer
    ret
print_and_check_ascii_value ENDP

print_and_save_value PROC adr :DWORD, number_of_bytes_read: DWORD
    invoke SetFilePointer, hFile, adr, NULL, FILE_BEGIN
    invoke ReadFile, hFile, addr buffer, number_of_bytes_read, addr bytesRead, NULL

    ; 4 dòng sau chuyển từ giá trị ascii sang decimal
    mov eax, offset buffer
    mov eax, DWORD PTR [eax]
    mov edi, offset string_decimal
    call to_string

    ; 5 dòng sau chuyển từ ascii sang hexa sau đó in ra console
    mov eax, offset buffer
    mov eax, DWORD PTR [eax]
    mov edi, offset string_hex
    call to_hex_string
    invoke StdOut, offset string_hex

    ; Chuyển từ string db sang số nguyên dword
    ; Load the address of source_string into esi
    lea esi, [string_decimal]
    ; Call atoi function to convert string to dword
    invoke atodw, esi
    mov signature, eax
    ret
print_and_save_value ENDP

print_decimal_value PROC adr :DWORD
    ; 4 dòng sau chuyển từ giá trị ascii sang decimal
    mov eax, adr
    ;mov eax, DWORD PTR [eax]
    mov edi, offset string_decimal
    call to_string
    invoke StdOut, offset string_decimal

    ; Chuyển từ string db sang số nguyên dword
    ; Load the address of source_string into esi
    ; lea esi, [string_decimal]
    ; ; Call atoi function to convert string to dword
    ; invoke atodw, esi
    ; mov signature, eax
    ; lea esi, [string_decimal]
    ; ; Call atoi function to convert string to dword
    ; invoke atodw, esi
    ; mov size_of_optional_header, eax
    ; Reset giá trị của chuỗi về rỗng
    ; mov eax, offset string_decimal ; Con trỏ đến chuỗi
    ; mov ecx, sizeof string_decimal ; Độ dài của chuỗi
    ; xor edx, edx ; Giá trị để gán (0)
    ; rep stosb ; Lặp qua từng byte và gán giá trị 0
    ret
print_decimal_value ENDP




print_and_save_value_of_size_of_optional_header PROC adr :DWORD, number_of_bytes_read: DWORD
    invoke SetFilePointer, hFile, adr, NULL, FILE_BEGIN
    invoke ReadFile, hFile, addr buffer, number_of_bytes_read, addr bytesRead, NULL

    ; 4 dòng sau chuyển từ giá trị ascii sang decimal
    mov eax, offset buffer
    mov eax, DWORD PTR [eax]
    mov edi, offset string_decimal
    call to_string
    ; invoke StdOut, offset string_decimal
    ; invoke StdOut,offset newline

    ; 5 dòng sau chuyển từ ascii sang hexa sau đó in ra console
    mov eax, offset buffer
    mov eax, DWORD PTR [eax]
    mov edi, offset string_hex
    call to_hex_string
    invoke StdOut, offset string_hex

    ; Chuyển từ string db sang số nguyên dword
    ; Load the address of source_string into esi
    lea esi, [string_decimal]
    ; Call atoi function to convert string to dword
    invoke atodw, esi
    mov size_of_optional_header, eax
    ret
print_and_save_value_of_size_of_optional_header ENDP

print_and_save_value_of_magic PROC adr :DWORD

    ; 4 dòng sau chuyển từ giá trị ascii sang decimal
    mov eax, adr
    mov eax, DWORD PTR [eax]
    mov edi, offset string_decimal
    call to_string

    ; Chuyển từ string db sang số nguyên dword
    lea esi, [string_decimal]
    ; Call atoi function to convert string to dword
    invoke atodw, esi
    mov ma_gic, eax
    ret
print_and_save_value_of_magic ENDP

print_and_save_value_of_size_of_section PROC adr :DWORD, number_of_bytes_read: DWORD
    invoke SetFilePointer, hFile, adr, NULL, FILE_BEGIN
    invoke ReadFile, hFile, addr buffer, number_of_bytes_read, addr bytesRead, NULL

    ; 4 dòng sau chuyển từ giá trị ascii sang decimal
    mov eax, offset buffer
    mov eax, DWORD PTR [eax]
    mov edi, offset string_decimal
    call to_string
    ; invoke StdOut, offset string_decimal
    ; invoke StdOut,offset newline

    ; 5 dòng sau chuyển từ ascii sang hexa sau đó in ra console
    mov eax, offset buffer
    mov eax, DWORD PTR [eax]
    mov edi, offset string_hex
    call to_hex_string
    invoke StdOut, offset string_hex

    ; Chuyển từ string db sang số nguyên dword
    lea esi, [string_decimal]
    ; Call atoi function to convert string to dword
    invoke atodw, esi
    mov number_of_section, eax
    ret
print_and_save_value_of_size_of_section ENDP

; In va luu gia tri Import directory RVA
print_and_save_value_of_import_directory_rva PROC adr :DWORD, number_of_bytes_read: DWORD
    invoke SetFilePointer, hFile, adr, NULL, FILE_BEGIN
    invoke ReadFile, hFile, addr buffer, number_of_bytes_read, addr bytesRead, NULL

    ; 5 dòng sau chuyển từ ascii sang hexa sau đó in ra console
    mov eax, offset buffer
    mov eax, DWORD PTR [eax]
    mov edi, offset string_hex
    call to_hex_string
    invoke StdOut, offset string_hex
    ; 4 dòng sau chuyển từ giá trị ascii sang decimal
    mov eax, offset buffer
    mov eax, DWORD PTR [eax]
    mov edi, offset string_decimal
    call to_string
    ; invoke StdOut, offset string_decimal
    ; invoke StdOut,offset newline


    ; Chuyển từ string db sang số nguyên dword
    ; Load the address of source_string into esi
    lea esi, [string_decimal]
    ; Call atoi function to convert string to dword
    invoke atodw, esi
    mov importDirectoryRVA_, eax
    ret
print_and_save_value_of_import_directory_rva ENDP

print_and_save_value_of_export_directory_rva PROC adr :DWORD, number_of_bytes_read: DWORD
    invoke SetFilePointer, hFile, adr, NULL, FILE_BEGIN
    invoke ReadFile, hFile, addr buffer, number_of_bytes_read, addr bytesRead, NULL

    ; 5 dòng sau chuyển từ ascii sang hexa sau đó in ra console
    mov eax, offset buffer
    mov eax, DWORD PTR [eax]
    mov edi, offset string_hex
    call to_hex_string
    invoke StdOut, offset string_hex
    ; 4 dòng sau chuyển từ giá trị ascii sang decimal
    mov eax, offset buffer
    mov eax, DWORD PTR [eax]
    mov edi, offset string_decimal
    call to_string
    ; invoke StdOut, offset string_decimal
    ; invoke StdOut,offset newline


    ; Chuyển từ string db sang số nguyên dword
    ; Load the address of source_string into esi
    lea esi, [string_decimal]
    ; Call atoi function to convert string to dword
    invoke atodw, esi
    mov exportDirectoryRVA_, eax
    ret
print_and_save_value_of_export_directory_rva ENDP


; In va luu gia tri cua rdata offset raw
print_and_save_value_of_rdat_offset_raw PROC adr :DWORD, number_of_bytes_read: DWORD
    invoke SetFilePointer, hFile, adr, NULL, FILE_BEGIN
    invoke ReadFile, hFile, addr buffer, number_of_bytes_read, addr bytesRead, NULL

    ; 4 dòng sau chuyển từ giá trị ascii sang decimal
    mov eax, offset buffer
    mov eax, DWORD PTR [eax]
    mov edi, offset string_decimal
    call to_string
    ; invoke StdOut, offset string_decimal
    ; invoke StdOut,offset newline

    ; 5 dòng sau chuyển từ ascii sang hexa sau đó in ra console
    mov eax, offset buffer
    mov eax, DWORD PTR [eax]
    mov edi, offset string_hex
    call to_hex_string
    invoke StdOut, offset string_hex

    ; Chuyển từ string db sang số nguyên dword
    ; Load the address of source_string into esi
    lea esi, [string_decimal]
    ; Call atoi function to convert string to dword
    invoke atodw, esi
    mov rDataRawAddress, eax
    ret
print_and_save_value_of_rdat_offset_raw ENDP

; In va luu gia tri cua rdata virtual address
print_and_save_value_of_rdat_virtual_address PROC adr :DWORD, number_of_bytes_read: DWORD
    invoke SetFilePointer, hFile, adr, NULL, FILE_BEGIN
    invoke ReadFile, hFile, addr buffer, number_of_bytes_read, addr bytesRead, NULL

    ; 4 dòng sau chuyển từ giá trị ascii sang decimal
    mov eax, offset buffer
    mov eax, DWORD PTR [eax]
    mov edi, offset string_decimal
    call to_string
    ; invoke StdOut, offset string_decimal
    ; invoke StdOut,offset newline

    ; 5 dòng sau chuyển từ ascii sang hexa sau đó in ra console
    mov eax, offset buffer
    mov eax, DWORD PTR [eax]
    mov edi, offset string_hex
    call to_hex_string
    invoke StdOut, offset string_hex

    ; Chuyển từ string db sang số nguyên dword
    ; Load the address of source_string into esi
    lea esi, [string_decimal]
    ; Call atoi function to convert string to dword
    invoke atodw, esi
    mov rDataVirtualAddress, eax
    ret
print_and_save_value_of_rdat_virtual_address ENDP


to_hex_string PROC
    mov ebx, 16 ; Gán ebx giá trị 16 (cơ số của số hexa).
    xor ecx, ecx ; Đặt ecx bằng 0 (đếm số chữ số).

repeated_division:
    xor edx, edx ; Đặt edx bằng 0 để chứa phần dư.
    div ebx ; Thực hiện phép chia eax cho ebx, kết quả là eax chứa phần nguyên, edx chứa phần dư.
    push dx ; Đẩy phần dư (dx) vào stack.
    add cl, 1 ; Tăng ecx lên 1 (đếm số chữ số).
    or eax, eax ; Kiểm tra xem eax còn giá trị không (không bằng 0).
    jnz repeated_division ; Nếu còn giá trị, tiếp tục vòng lặp.

load_digits:
    pop ax ; Lấy giá trị từ stack vào ax.
    cmp al, 10 ; So sánh giá trị với 10.
    jl convert_digit ; Nếu giá trị nhỏ hơn 10, chuyển sang convert_digit.
    add al, 'A' - 10 ; Nếu giá trị lớn hơn hoặc bằng 10, chuyển đổi thành ký tự từ 'A' đến 'F'.
    jmp store_digit ; Tiếp tục vòng lặp store_digit.

convert_digit:
    or al, 30h ; Chuyển giá trị thành ký tự ASCII tương ứng.

store_digit:
    stosb ; Lưu ký tự vào edi (địa chỉ của string_hex) và tăng edi lên 1.
    loop load_digits ; Lặp lại cho tất cả các chữ số.
    mov byte ptr [edi], 0 ; Gán giá trị null (ký tự kết thúc chuỗi) vào vị trí cuối cùng của chuỗi.
    ret ; Kết thúc hàm.
to_hex_string ENDP

; Ham chuyen ascii sang decimal
to_string PROC
    mov ebx, 10
    xor ecx,ecx

repeated_division:
    xor edx,edx
    div ebx
    push dx
    add cl,1
    or eax,eax
    jnz repeated_division

load_digits:
    pop ax
    or al, 00110000b
    stosb
    loop load_digits
    mov byte ptr [edi], 0
    ret
to_string ENDP

main PROC

    invoke ReadConsoleA, GetStdHandle(STD_INPUT_HANDLE), addr fileName, 256, addr bytesRead, 0
    
    ; Open the file
    invoke CreateFileA, addr fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    mov ebx, eax ; ebx = file handle
    mov hFile, ebx

    ; Check if the file is valid
    cmp ebx, INVALID_HANDLE_VALUE
    je cleanup

    ; Allocate memory for the file using VirtualAlloc
    ; invoke GetFileSize, ebx, NULL
    ; mov edx, eax
    ;invoke VirtualAlloc, NULL, edx, MEM_COMMIT, PAGE_READWRITE
    ;mov edi, eax ; edi = fileData

    ; Read the file into memory
    ;invoke ReadFile, hFile, addr Buffer, edx, addr bytesRead, NULL

    ; Dos Header
    invoke StdOut, offset dosHeader
    invoke StdOut, offset newline
    invoke StdOut, offset eMagic        ; e_magic part   
    invoke print_value, 0, 2  
    invoke StdOut, offset newline      
    invoke StdOut, offset eCblp         ; e_cblp part 
    invoke print_value, 2, 2 
    invoke StdOut, offset newline
    invoke StdOut, offset eCp           ; e_cblp part  
    invoke print_value, 4, 2 
    invoke StdOut, offset newline
    invoke StdOut, offset eCp           ; e_crlc part, so luong relocations can dieu chinh trong DOS   
    invoke print_value, 6, 2 
    invoke StdOut, offset newline
    invoke StdOut, offset eCparhdr      ; So luong  paragraph trong header cua tap tin DOS
    invoke print_value, 8, 2
    invoke StdOut, offset newline 
    invoke StdOut, offset eMinalloc     ; So luong paragraph toi thieu can trong qua trinh thuc thi
    invoke print_value, 10, 2
    invoke StdOut, offset newline
    invoke StdOut, offset eMaxalloc     ; So luong paragraph toi da can trong qua trinh thuc thi
    invoke print_value, 12, 2
    invoke StdOut, offset newline
    invoke StdOut, offset eSs           ; Segment cua stack cho chuong trinh DOS
    invoke print_value,14, 2
    invoke StdOut, offset newline
    invoke StdOut, offset e_Sp           ; Offset trong stack segment cho stack pointer
    invoke print_value,16, 2
    invoke StdOut, offset newline
    invoke StdOut, offset eCsum           ; Checksum
    invoke print_value,18, 2
    invoke StdOut, offset newline
    invoke StdOut, offset e_Ip           ; Offset trong code segment cho instruction pointer
    invoke print_value,20, 2
    invoke StdOut, offset newline
    invoke StdOut, offset eCs           ; Segment cua code cho chuong trinh DOS
    invoke print_value,22, 2
    invoke StdOut, offset newline
    invoke StdOut, offset eLfarlc           ; Offset trong file cua bang relocation
    invoke print_value,24, 2
    invoke StdOut, offset newline
    invoke StdOut, offset eOvno           ; So luong trung lap cua tap tin DOS (Overlay number)
    invoke print_value,26, 2
    invoke StdOut, offset newline
    invoke StdOut, offset eRes           ; Cac gia tri du phong khong duoc su dung
    invoke print_value,28, 8
    invoke StdOut, offset newline
    invoke StdOut, offset eOemid           ; Xac dinh nha san xuat OEM cua tap tin DOS
    invoke print_value,36, 2
    invoke StdOut, offset newline
    invoke StdOut, offset eOeminfo           ; Thong tin cu the cua OEM
    invoke print_value,38, 2
    invoke StdOut, offset newline
    invoke StdOut, offset eRes2           ; Khong duoc su dung trong DOS Header
    invoke print_value,40, 20
    invoke StdOut, offset newline
    invoke StdOut, offset eLfanew           ; Chua offset cua NT Header
    invoke print_and_save_value,60, 2
    ;-------------------------------------------------------------------------------------

    ; NT Header
    ; Signature
    invoke StdOut, offset newline
    invoke StdOut, offset newline
    invoke StdOut, offset ntHeaders
    invoke StdOut, offset newline
    invoke StdOut, offset signatures
    invoke print_value,signature, 2

    ; File Header
    invoke StdOut, offset newline
    invoke StdOut, offset newline
    invoke StdOut, offset fileHeaders
    invoke StdOut, offset newline               ; Ky tu xuong dong
    invoke StdOut, offset machine              ; Machine xac dinh kieu kien truc may tinh muc tieu ma tep PE nay duoc thiet ke de chay
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 4 to signature
    invoke print_value,signature, 2            ; signature luc nay la index cua machine     
    invoke StdOut, offset newline               ; Ky tu xuong dong
    invoke StdOut, offset numberOfSections      ; So luong section trong PE
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 2                      ; Add 2 to signature
    invoke print_and_save_value_of_size_of_section,signature, 2            ; signature luc nay la index cua number of section     
    invoke StdOut, offset newline               ; Ky tu xuong dong
    invoke StdOut, offset timeDateStamp                ; Thoi gian tao file PE
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 2                      ; Add 2 to signature
    invoke print_value,signature, 4            ; signature luc nay la index cua timedatestamp
    invoke StdOut, offset newline               ; Ky tu xuong dong
    invoke StdOut, offset pointerToSymbolTable                ; Vi tri Symbol table
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 2 to signature
    invoke print_value,signature, 4            ; signature luc nay la index cua pointertosymboltable
    invoke StdOut, offset newline               ; Ky tu xuong dong
    invoke StdOut, offset numberOfSymbols                ; So luong symbol trong bang ky hieu
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 2 to signature
    invoke print_value,signature, 4            ; signature luc nay la index cua number of symbol
    invoke StdOut, offset newline               ; Ky tu xuong dong
    invoke StdOut, offset sizeOfOptionalHeaders                ; Kich thuoc cua optional header
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 2 to signature
    invoke print_and_save_value_of_size_of_optional_header,signature, 2            ; signature luc nay la index cua size of optional header
    invoke StdOut, offset newline               ; Ky tu xuong dong
    invoke StdOut, offset characteristics                ; Chua cac flag chi dinh thuoc tinh cua PE
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 2                      ; Add 2 to signature
    invoke print_value,signature, 2            ; signature luc nay la index cua characteristics

    ; Optional header
    invoke StdOut, offset newline
    invoke StdOut, offset newline
    invoke StdOut, offset optionalHeader
    invoke StdOut, offset newline               ; Ky tu xuong dong
    invoke StdOut, offset magic                 ; Xac dinh loai cua Optional Header
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 2   
    ;mov ma_gic,eax
    invoke print_and_save_value_of_magic, eax
    invoke print_value,signature, 2
    ;invoke print_decimal_value, eax
    ;mov ma_gic,signature                   ; Add 2 to signature
    ;invoke StdOut, offset signature
    ;invoke print_and_save_value,signature, 2            ; signature luc nay la index cua magic
    invoke StdOut, offset newline               ; Ky tu xuong dong
    invoke StdOut, offset majorLinkerVersion    ; Thong tin cua linker dung de tao PE
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 2                      ; Add 1 to signature
    invoke print_value,signature, 1            ; signature luc nay la index cua majorlinkerversion
    invoke StdOut, offset newline               ; Ky tu xuong dong
    invoke StdOut, offset minorLinkerVersion    ; Thong tin cua linker dung de tao PE
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 1                      ; Add 2 to signature
    invoke print_value,signature, 1         
    invoke StdOut, offset newline               ; Ky tu xuong dong
    invoke StdOut, offset sizeOfCode            ; Kich thuoc phan ma may trong PE
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 1                      ; Add 2 to signature
    invoke print_value,signature, 4  
    invoke StdOut, offset newline               ; Ky tu xuong dong
    invoke StdOut, offset sizeOfInitializedData    ; Kich thuoc phan du lieu da khoi tao
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 2 to signature
    invoke print_value,signature, 4  
    invoke StdOut, offset newline               ; Ky tu xuong dong
    invoke StdOut, offset sizeOfUninitializedData    ; Kich thuoc phan du lieu chua duoc khoi tao
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 2 to signature
    invoke print_value,signature, 4     
    invoke StdOut, offset newline               ; Ky tu xuong dong
    invoke StdOut, offset addressOfEntryPoint    ; Chua dia chi EP, la noi chuong trinh bat dau thuc thi
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 2 to signature
    invoke print_value,signature, 4  
    invoke StdOut, offset newline               ; Ky tu xuong dong
    invoke StdOut, offset baseOfCode            ; Dia chi co so cua ma may khi PE duoc tai len mem
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 2 to signature
    invoke print_value,signature, 4  
    invoke StdOut, offset newline               ; Ky tu xuong dong
    invoke StdOut, offset baseOfData            ; Dia chi co so cua data khi PE duoc tai len mem
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 2 to signature
    invoke print_value,signature, 4  
    invoke StdOut, offset newline               ; Ky tu xuong dong
    invoke StdOut, offset imageBase            ; Dia chi co so cua PE khi duoc tai len mem (Image Base)
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 2 to signature
    invoke print_value,signature, 4  
    invoke StdOut, offset newline               ; Ky tu xuong dong
    invoke StdOut, offset sectionAlignment      ; Xac dinh phan can chinh cua section trong bo nho
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 2 to signature
    invoke print_value,signature, 4  
    invoke StdOut, offset newline               ; Ky tu xuong dong
    invoke StdOut, offset fileAlignment      ; Xac dinh phan can chinh cua section trong file
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 2 to signature
    invoke print_value,signature, 4 
    invoke StdOut, offset newline               ; Ky tu xuong dong
    invoke StdOut, offset majorOperatingSystemVersion      ; Chua thong tin ve he dieu hanh muc tieu cho file PE
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 2 to signature
    invoke print_value,signature, 2
    invoke StdOut, offset newline               ; Ky tu xuong dong
    invoke StdOut, offset minorOperatingSystemVersion      ; Chua thong tin ve he dieu hanh muc tieu cho file PE
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 2                      ; Add 2 to signature
    invoke print_value,signature, 2

    invoke StdOut, offset newline               ; Ky tu xuong dong
    invoke StdOut, offset majorImageVersion      ; Xac dinh phien ban cua tep PE
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 2                      ; Add 2 to signature
    invoke print_value,signature, 2
    invoke StdOut, offset newline               ; Ky tu xuong dong
    invoke StdOut, offset minorImageVersion      ; Xac dinh phien ban cua tep PE
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 2                      ; Add 2 to signature
    invoke print_value,signature, 2
    invoke StdOut, offset newline               ; Ky tu xuong dong
    invoke StdOut, offset majorSubsystemVersion ; Chua thong tin ve phien ban subsytem ma file PE can de chay
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 2                      ; Add 2 to signature
    invoke print_value,signature, 2
    invoke StdOut, offset newline               ; Ky tu xuong dong
    invoke StdOut, offset minorSubsystemVersion ; Chua thong tin ve phien ban subsytem ma file PE can de chay
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 2                      ; Add 2 to signature
    invoke print_value,signature, 2
    invoke StdOut, offset newline               ; Ky tu xuong dong
    invoke StdOut, offset win32version 
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 2                      ; Add 2 to signature
    invoke print_value,signature, 4
    invoke StdOut, offset newline               ; Ky tu xuong dong
    invoke StdOut, offset sizeOfImage           ; Kich thuoc toi da cua file khi tai len mem
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 2 to signature
    invoke print_value,signature, 4
    invoke StdOut, offset newline               ; Ky tu xuong dong
    invoke StdOut, offset sizeOfHeader          ; Kich thuoc toi da cua tat cac cac phan header trong tep PE
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 2 to signature
    invoke print_value,signature, 4
    invoke StdOut, offset newline               ; Ky tu xuong dong
    invoke StdOut, offset checksum              ; Chua gia tri kiem tra de kiem tra tinh toan ven cua PE
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 2 to signature
    invoke print_value,signature, 4
    invoke StdOut, offset newline               ; Ky tu xuong dong
    invoke StdOut, offset subsystem             ; Xac dinh subsystem cua he thong
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 2 to signature
    invoke print_value,signature, 2
    invoke StdOut, offset newline               ; Ky tu xuong dong
    invoke StdOut, offset dllCharacteristics      ; Chua cac dac diem cho biet file PE co phai file DLL hay khong
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 2                      ; Add 2 to signature
    invoke print_value,signature, 2
    invoke StdOut, offset newline               ; Ky tu xuong dong
    invoke StdOut, offset sizeOfStackReserve      ; Xac dinh kich thuoc stack duoc luu tru va cap phat khi load
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 2                      ; Add 2 to signature
    invoke print_value,signature, 4
    invoke StdOut, offset newline               ; Ky tu xuong dong
    invoke StdOut, offset sizeOfStackCommit      ; Xac dinh kich thuoc stack duoc luu tru va cap phat khi load
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 2 to signature
    invoke print_value,signature, 4
    invoke StdOut, offset newline               ; Ky tu xuong dong
    invoke StdOut, offset sizeOfHeapReserve      ; Xac dinh kich thuoc heap duoc luu tru va cap phat khi load
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 2 to signature
    invoke print_value,signature, 4
    invoke StdOut, offset newline               ; Ky tu xuong dong
    invoke StdOut, offset sizeOfHeapCommit      ; Xac dinh kich thuoc heap duoc luu tru va cap phat khi load
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 2 to signature
    invoke print_value,signature, 4
    invoke StdOut, offset newline               ; Ky tu xuong dong
    invoke StdOut, offset loaderFlag            ; Co lien quan de qua trinh load, khong duoc su dung nhieu
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 2 to signature
    invoke print_value,signature, 4
    invoke StdOut, offset newline               ; Ky tu xuong dong
    invoke StdOut, offset numberOfRvaAndSizes   ; Xac dinh so luong muc trong mang data directory
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 2 to signature
    invoke print_value,signature, 4
    
    ; Data Directories
    invoke StdOut, offset newline
    invoke StdOut, offset newline
    invoke StdOut, offset dataDirectory
    invoke StdOut, offset newline
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 4 to signature
    invoke StdOut,offset exportDirectoryRVA
    invoke print_and_save_value_of_export_directory_rva,signature, 4
    invoke StdOut, offset newline
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 4 to signature
    invoke StdOut,offset exportDirectorySize
    invoke print_value,signature, 4
    invoke StdOut, offset newline

    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 4 to signature
    invoke StdOut,offset importDirectoryRVA
    invoke print_and_save_value_of_import_directory_rva,signature, 4
    invoke StdOut, offset newline
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 4 to signature
    invoke StdOut,offset importDirectorySize
    invoke print_value,signature, 4
    invoke StdOut, offset newline

    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 4 to signature
    invoke StdOut,offset resourceDirectoryRVA
    invoke print_value,signature, 4
    invoke StdOut, offset newline
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 4 to signature
    invoke StdOut,offset resourceDirectorySize
    invoke print_value,signature, 4
    invoke StdOut, offset newline

    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 4 to signature
    invoke StdOut,offset exceptionDirectoryRVA
    invoke print_value,signature, 4
    invoke StdOut, offset newline
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 4 to signature
    invoke StdOut,offset exceptionDirectorySize
    invoke print_value,signature, 4
    invoke StdOut, offset newline

    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 4 to signature
    invoke StdOut,offset securityDirectoryRVA
    invoke print_value,signature, 4
    invoke StdOut, offset newline
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 4 to signature
    invoke StdOut,offset securityDirectorySize
    invoke print_value,signature, 4
    invoke StdOut, offset newline

    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 4 to signature
    invoke StdOut,offset relocationDirectoryRVA
    invoke print_value,signature, 4
    invoke StdOut, offset newline
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 4 to signature
    invoke StdOut,offset relocationDirectorySize
    invoke print_value,signature, 4
    invoke StdOut, offset newline

    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 4 to signature
    invoke StdOut,offset debugDirectoryRVA
    invoke print_value,signature, 4
    invoke StdOut, offset newline
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 4 to signature
    invoke StdOut,offset debugDirectorySize
    invoke print_value,signature, 4
    invoke StdOut, offset newline

    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 4 to signature
    invoke StdOut,offset architectureDirectoryRVA
    invoke print_value,signature, 4
    invoke StdOut, offset newline
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 4 to signature
    invoke StdOut,offset architectureDirectorySize
    invoke print_value,signature, 4
    invoke StdOut, offset newline

    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 4 to signature
    invoke StdOut,offset reserved
    invoke print_value,signature, 4
    invoke StdOut, offset newline
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 4 to signature
    invoke StdOut,offset reserved
    invoke print_value,signature, 4
    invoke StdOut, offset newline

    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 4 to signature
    invoke StdOut,offset tlsDirectoryRVA
    invoke print_value,signature, 4
    invoke StdOut, offset newline
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 4 to signature
    invoke StdOut,offset tlsDirectorySize
    invoke print_value,signature, 4
    invoke StdOut, offset newline

    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 4 to signature
    invoke StdOut,offset configurationDirectoryRVA
    invoke print_value,signature, 4
    invoke StdOut, offset newline
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 4 to signature
    invoke StdOut,offset configurationDirectorySize
    invoke print_value,signature, 4
    invoke StdOut, offset newline

    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 4 to signature
    invoke StdOut,offset boundImportDirectoryRVA
    invoke print_value,signature, 4
    invoke StdOut, offset newline
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 4 to signature
    invoke StdOut,offset boundImportDirectorySize
    invoke print_value,signature, 4
    invoke StdOut, offset newline

    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 4 to signature
    invoke StdOut,offset importAddressTableDirectoryRVA
    invoke print_value,signature, 4
    invoke StdOut, offset newline
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 4 to signature
    invoke StdOut,offset importAddressTableDirectorySize
    invoke print_value,signature, 4
    invoke StdOut, offset newline
    
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 4 to signature
    invoke StdOut,offset delayImportDirectoryRVA
    invoke print_value,signature, 4
    invoke StdOut, offset newline
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 4 to signature
    invoke StdOut,offset delayImportDirectorySize
    invoke print_value,signature, 4
    invoke StdOut, offset newline

    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 4 to signature
    invoke StdOut,offset netMetadataDirectoryRVA
    invoke print_value,signature, 4
    invoke StdOut, offset newline
    lea eax, [signature]                        ;Load the address of signature into eax
    add dword ptr [eax], 4                      ; Add 4 to signature
    invoke StdOut,offset netMetadataDirectorySize
    invoke print_value,signature, 4
    invoke StdOut, offset newline
    
    

    ; Section Headers
    invoke StdOut, offset newline
    invoke StdOut, offset sectionHeader
    invoke StdOut, offset newline
    mov eax, size_of_optional_header                ; Lay gia tri size cua optional header
    add eax, ma_gic                                 ; Cong voi gia tri dia chi dau tien cua optional header
    mov section,eax                                 ; Luu vao bien section lam dia chi bat dau cua Section header

    ; Vong lap de hien thi cac section trong file PE
    mov ecx, number_of_section
    FOR_LOOP:
        push ecx                                    ; push ecx vao stack de gia tri ben trong vong lap khong anh huong den gia tri ecx ben ngoai
        invoke print_and_check_ascii_value,section,6
        ;invoke StdOut, offset rdata_
        invoke StdOut, offset newline
        add section,8
        invoke StdOut, offset virtualSize
        invoke print_value,section,4
        invoke StdOut, offset newline
        add section,4
        invoke StdOut, offset virtualAddress
        invoke print_value,section,4
        invoke StdOut, offset newline
        add section,4
        invoke StdOut, offset sizeOfRawData
        invoke print_value,section,4
        invoke StdOut, offset newline
        add section,4
        invoke StdOut, offset pointerToRawData
        invoke print_value,section,4
        invoke StdOut, offset newline
        add section,4
        invoke StdOut, offset pointerToRelocations
        invoke print_value,section,4
        invoke StdOut, offset newline
        add section,4
        invoke StdOut, offset pointerToLineNumbers
        invoke print_value,section,4
        invoke StdOut, offset newline
        add section,4
        invoke StdOut, offset numberOfRelocations
        invoke print_value,section,2
        invoke StdOut, offset newline
        add section,2
        invoke StdOut, offset numberOfLineNumbers
        invoke print_value,section,2
        invoke StdOut, offset newline
        add section,2
        invoke StdOut, offset characteristics1
        invoke print_value,section,4
        invoke StdOut, offset newline
        add section,4
        pop ecx                                         ; pop ecx ra khoi stack
        dec ecx
        jnz FOR_LOOP
        
    ;invoke print_value,2264,4
    ; DLL Import
    invoke StdOut, offset newline
    invoke StdOut, offset dllImport
    invoke StdOut, offset newline

    cmp importDirectoryRVA_,0
    je END_READING_LOOP

    ; Tinh offset cua import
    mov eax, importDirectoryRVA_
    sub eax, rDataVirtualAddress
    add eax, rDataRawAddress
    mov import_oft_offset, eax
    ;invoke print_value, import_oft_offset,8

    READ_DLL_IMPORT_LOOP:
        ; Luu gia tri vao bien
        invoke save_value_of_import_oft,import_oft_offset,4

        ; cmp import_oft,0
        ; je END_READING_LOOP

        MOV ECX, LENGTHOF check1 ; Độ dài của chuỗi
        MOV ESI, OFFSET check1   ; Con trỏ của chuỗi 1
        MOV EDI, OFFSET import_oft   ; Con trỏ của chuỗi 2
        REPE CMPSB                 ; So sánh từng byte của hai chuỗi
        JZ END_READING_LOOP 

        ;invoke print_decimal_value, import_oft
        ;invoke print_ascii_value, 2148,4

        ; Tinh offset cua import
        mov eax, import_oft_offset
        add eax, 12
        mov importNameRVA, eax
        ; invoke print_decimal_value,importNameRVA
        ; invoke StdOut, offset newline

        

        mov eax, import_oft
        sub eax, rDataVirtualAddress
        add eax, rDataRawAddress
        mov import_lib_oft, eax 
        ;invoke save_value_of_import_lib,eax,4

        invoke save_value_of_lib_name_offet,importNameRVA,4
        mov eax, lib_name_offset
        sub eax, rDataVirtualAddress
        add eax, rDataRawAddress
        invoke print_ascii_value,eax,20
        invoke StdOut, offset newline

        invoke StdOut, offset ofts_column
        invoke StdOut, offset tab
        invoke StdOut, offset tab
        invoke StdOut, offset fts_column
        invoke StdOut, offset tab
        invoke StdOut, offset tab
        invoke StdOut, offset name_column
        invoke StdOut, offset newline

        ; invoke print_decimal_value,lib_name_offset
        ; invoke StdOut, offset newline

        ; mov eax, offset buffer
        ; sub eax, rDataVirtualAddress
        ; add eax, rDataRawAddress
        WHILE_LOOP:
            invoke save_value_of_import_lib,import_lib_oft,4

            MOV ECX, LENGTHOF check ; Độ dài của chuỗi
            MOV ESI, OFFSET check   ; Con trỏ của chuỗi 1
            MOV EDI, OFFSET import_lib   ; Con trỏ của chuỗi 2
            REPE CMPSB                 ; So sánh từng byte của hai chuỗi
            JZ END_WHILE_LOOP         ; Nếu chuỗi giống nhau, nhảy tới nhãn strings_equal1

            invoke StdOut, offset hex
            invoke print_value, import_lib_oft, 8
            invoke StdOut, offset tab
            invoke StdOut, offset tab
            invoke StdOut, offset hex
            invoke print_value, import_lib_oft, 8
            invoke StdOut, offset tab

            mov eax, import_lib
            sub eax, rDataVirtualAddress
            add eax, rDataRawAddress
            mov temp1,eax


            strings_not_equal1:
                add temp1,2
                invoke StdOut, offset tab
                invoke print_ascii_value,temp1,20
                invoke StdOut, offset newline
                mov eax,import_lib_oft
                add eax,4
                mov import_lib_oft,eax
                jmp WHILE_LOOP
        END_WHILE_LOOP:

        mov eax, import_oft_offset
        add eax,20
        mov import_oft_offset,eax
        jmp READ_DLL_IMPORT_LOOP
    
    END_READING_LOOP:
    
    ; DLL Export
    invoke StdOut, offset newline
    invoke StdOut, offset dllExport
    invoke StdOut, offset newline
    cmp importDirectoryRVA_,0
    je END_READING_LOOP
    ;invoke print_ascii_value,320345,20
    ; invoke print_decimal_value, exportDirectoryRVA_
    ; invoke StdOut, offset newline
    mov eax, exportDirectoryRVA_
    sub eax, rDataVirtualAddress
    add eax, rDataRawAddress
    add eax, 40
    mov functionRVA, eax

    invoke StdOut, offset functionRVA_column
    invoke StdOut, offset tab
    invoke StdOut, offset tab
    invoke StdOut, offset nameRVA_column
    invoke StdOut, offset tab
    invoke StdOut, offset tab
    invoke StdOut, offset name_column
    invoke StdOut, offset newline

    ;invoke print_decimal_value, rDataRawAddress
    PRINT_EXPORT_DLL_LOOP:
        invoke StdOut, offset hex
        invoke print_value, functionRVA, 4
        invoke StdOut, offset tab
        invoke StdOut, offset tab
        invoke StdOut, offset tab
        mov eax, functionRVA
        add eax, 64
        mov export_name_rva_temp, eax
        invoke save_value_of_export_name_rva,export_name_rva_temp,4
        invoke StdOut, offset hex
        invoke print_value, export_name_rva_temp, 4
        invoke StdOut, offset tab
        MOV ECX, LENGTHOF check ; Độ dài của chuỗi
        MOV ESI, OFFSET check   ; Con trỏ của chuỗi 1
        MOV EDI, OFFSET export_temp   ; Con trỏ của chuỗi 2
        REPE CMPSB                 ; So sánh từng byte của hai chuỗi
        JZ END_PRINT_EXPORT_DLL_LOOP 
        ;invoke print_ascii_value,315740,20
        mov eax, export_temp
        sub eax, rDataVirtualAddress
        add eax, rDataRawAddress
        mov export_name_offet, eax
        invoke StdOut, offset tab
        invoke print_ascii_value, export_name_offet, 20
        invoke StdOut, offset newline
        add functionRVA,4
        jmp PRINT_EXPORT_DLL_LOOP
    END_PRINT_EXPORT_DLL_LOOP:


cleanup:
    ; Close file handle
    invoke CloseHandle, ebx

    ; Free allocated memory
    invoke GetProcessHeap
    mov ebx, eax   ; Save the heap handle in ebx (optional, if you need it later)
    invoke HeapFree, ebx, NULL, edi


    ; Exit program
    invoke ExitProcess, 0

main ENDP
END main
