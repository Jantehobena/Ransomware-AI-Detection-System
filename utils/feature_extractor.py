# File: ransomware_scanner/utils/feature_extractor.py

import os
import pefile
import math

# Calculate entropy
def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(chr(x).encode('latin1'))) / len(data)
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return entropy

# Extract features
def extract_features(pe: pefile.PE, filepath: str) -> dict:
    try:
        features = {}

        # Basic file features
        features['file_size'] = os.path.getsize(filepath)
        features['entropy'] = calculate_entropy(pe.__data__)

        # PE header fields
        features['EntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        features['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
        features['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
        features['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
        features['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
        features['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
        features['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
        features['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
        features['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        features['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
        features['BaseOfData'] = getattr(pe.OPTIONAL_HEADER, 'BaseOfData', 0)
        features['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
        features['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
        features['Checksum'] = pe.OPTIONAL_HEADER.CheckSum
        features['SizeofStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
        features['SizeofStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
        features['SizeofHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
        features['SizeofHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit

        # Sections
        if hasattr(pe, 'sections') and pe.sections:
            text_section = next((s for s in pe.sections if b'.text' in s.Name), None)
            rdata_section = next((s for s in pe.sections if b'.rdata' in s.Name), None)

            if text_section:
                features['text_VirtualSize'] = text_section.Misc_VirtualSize
                features['text_VirtualAddress'] = text_section.VirtualAddress
                features['text_SizeOfRawData'] = text_section.SizeOfRawData
                features['text_PointerToRawData'] = text_section.PointerToRawData
                features['text_Characteristics'] = text_section.Characteristics
            else:
                features['text_VirtualSize'] = 0
                features['text_VirtualAddress'] = 0
                features['text_SizeOfRawData'] = 0
                features['text_PointerToRawData'] = 0
                features['text_Characteristics'] = 0

            if rdata_section:
                features['rdata_VirtualSize'] = rdata_section.Misc_VirtualSize
                features['rdata_VirtualAddress'] = rdata_section.VirtualAddress
                features['rdata_SizeOfRawData'] = rdata_section.SizeOfRawData
                features['rdata_PointerToRawData'] = rdata_section.PointerToRawData
                features['rdata_Characteristics'] = rdata_section.Characteristics
            else:
                features['rdata_VirtualSize'] = 0
                features['rdata_VirtualAddress'] = 0
                features['rdata_SizeOfRawData'] = 0
                features['rdata_PointerToRawData'] = 0
                features['rdata_Characteristics'] = 0

        return features

    except Exception as e:
        return {}