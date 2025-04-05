from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import pickle
import pefile
import numpy as np
import pandas as pd
from werkzeug.utils import secure_filename
from sklearn.exceptions import InconsistentVersionWarning
import warnings

warnings.simplefilter("ignore", InconsistentVersionWarning)



best_model = pickle.load(open("CatBoost.pkl", "rb"))
predict_fn = lambda x: best_model.predict_proba(x)
features = [
"e_cblp","e_cp","e_crlc","e_cparhdr","e_minalloc","e_maxalloc","e_ss","e_sp","e_csum","e_ip","e_cs","e_lfarlc","e_ovno","e_oemid","e_oeminfo","e_lfanew","Machine","NumberOfSections","TimeDateStamp","PointerToSymbolTable","NumberOfSymbols","SizeOfOptionalHeader","Characteristics","Magic","MajorLinkerVersion","MinorLinkerVersion","SizeOfCode","SizeOfInitializedData","SizeOfUninitializedData","AddressOfEntryPoint","BaseOfCode","ImageBase","SectionAlignment","FileAlignment","MajorOperatingSystemVersion","MinorOperatingSystemVersion","MajorImageVersion","MinorImageVersion","MajorSubsystemVersion","MinorSubsystemVersion","SizeOfHeaders","CheckSum","SizeOfImage","Subsystem","DllCharacteristics","SizeOfStackReserve","SizeOfStackCommit","SizeOfHeapReserve","SizeOfHeapCommit","LoaderFlags","SectionsLength","SectionMinEntropy","SectionMinRawsize","SectionMinVirtualsize","SectionMaxPointerData","SectionMaxChar","DirectoryEntryImport","DirectoryEntryExport","ImageDirectoryEntryImport","ImageDirectoryEntryResource","ImageDirectoryEntryException"
]
def analyze(df):
    for i in range(len(df)):
        file_path = str(df.loc[i, "Name"])
        try:
            pe = pefile.PE(file_path)
        except:
            continue
        df.loc[i, "e_magic"] = pe.DOS_HEADER.e_magic
        df.loc[i, "e_cblp"] = pe.DOS_HEADER.e_cblp
        df.loc[i, "e_cp"] = pe.DOS_HEADER.e_cp
        df.loc[i, "e_crlc"] = pe.DOS_HEADER.e_crlc
        df.loc[i, "e_cparhdr"] = pe.DOS_HEADER.e_cparhdr
        df.loc[i, "e_minalloc"] = pe.DOS_HEADER.e_minalloc
        df.loc[i, "e_maxalloc"] = pe.DOS_HEADER.e_maxalloc
        df.loc[i, "e_ss"] = pe.DOS_HEADER.e_ss
        df.loc[i, "e_sp"] = pe.DOS_HEADER.e_sp
        df.loc[i, "e_csum"] = pe.DOS_HEADER.e_csum
        df.loc[i, "e_ip"] = pe.DOS_HEADER.e_ip
        df.loc[i, "e_cs"] = pe.DOS_HEADER.e_cs
        df.loc[i, "e_lfarlc"] = pe.DOS_HEADER.e_lfarlc
        df.loc[i, "e_ovno"] = pe.DOS_HEADER.e_ovno
        df.loc[i, "e_oemid"] = pe.DOS_HEADER.e_oemid
        df.loc[i, "e_oeminfo"] = pe.DOS_HEADER.e_oeminfo
        df.loc[i, "e_lfanew"] = pe.DOS_HEADER.e_lfanew
        df.loc[i, "Machine"] = pe.FILE_HEADER.Machine
        df.loc[i, "NumberOfSections"] = pe.FILE_HEADER.NumberOfSections
        df.loc[i, "TimeDateStamp"] = pe.FILE_HEADER.TimeDateStamp
        df.loc[i, "PointerToSymbolTable"] = pe.FILE_HEADER.PointerToSymbolTable
        df.loc[i, "NumberOfSymbols"] = pe.FILE_HEADER.NumberOfSymbols
        df.loc[i, "SizeOfOptionalHeader"] = pe.FILE_HEADER.SizeOfOptionalHeader
        df.loc[i, "Characteristics"] = pe.FILE_HEADER.Characteristics
        df.loc[i, "Magic"] = pe.OPTIONAL_HEADER.Magic
        df.loc[i, "MajorLinkerVersion"] = pe.OPTIONAL_HEADER.MajorLinkerVersion
        df.loc[i, "MinorLinkerVersion"] = pe.OPTIONAL_HEADER.MinorLinkerVersion
        df.loc[i, "SizeOfCode"] = pe.OPTIONAL_HEADER.SizeOfCode
        df.loc[i, "SizeOfInitializedData"] = pe.OPTIONAL_HEADER.SizeOfInitializedData
        df.loc[i, "SizeOfUninitializedData"] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
        df.loc[i, "AddressOfEntryPoint"] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        df.loc[i, "BaseOfCode"] = pe.OPTIONAL_HEADER.BaseOfCode
        df.loc[i, "ImageBase"] = pe.OPTIONAL_HEADER.ImageBase
        df.loc[i, "SectionAlignment"] = pe.OPTIONAL_HEADER.SectionAlignment
        df.loc[i, "FileAlignment"] = pe.OPTIONAL_HEADER.FileAlignment
        df.loc[i, "MajorOperatingSystemVersion"] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        df.loc[i, "MinorOperatingSystemVersion"] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
        df.loc[i, "MajorImageVersion"] = pe.OPTIONAL_HEADER.MajorImageVersion
        df.loc[i, "MinorImageVersion"] = pe.OPTIONAL_HEADER.MinorImageVersion
        df.loc[i, "MajorSubsystemVersion"] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
        df.loc[i, "MinorSubsystemVersion"] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
        df.loc[i, "SizeOfHeaders"] = pe.OPTIONAL_HEADER.SizeOfHeaders
        df.loc[i, "CheckSum"] = pe.OPTIONAL_HEADER.CheckSum
        df.loc[i, "SizeOfImage"] = pe.OPTIONAL_HEADER.SizeOfImage
        df.loc[i, "Subsystem"] = pe.OPTIONAL_HEADER.Subsystem
        df.loc[i, "DllCharacteristics"] = pe.OPTIONAL_HEADER.DllCharacteristics
        df.loc[i, "SizeOfStackReserve"] = pe.OPTIONAL_HEADER.SizeOfStackReserve
        df.loc[i, "SizeOfStackCommit"] = pe.OPTIONAL_HEADER.SizeOfStackCommit
        df.loc[i, "SizeOfHeapReserve"] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
        df.loc[i, "SizeOfHeapCommit"] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
        df.loc[i, "LoaderFlags"] = pe.OPTIONAL_HEADER.LoaderFlags
        df.loc[i, "NumberOfRvaAndSizes"] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
        df.loc[i, "SectionsLength"] = len(pe.sections)
        
        section_entropy_dict = {}
        for section in pe.sections:
            section_name = section.Name.decode('utf-8').strip('\x00')
            entropy = section.get_entropy()
            section_entropy_dict[section_name] = entropy
            
        df.loc[i, "SectionMinEntropy"] = min(section_entropy_dict.values())
        df.loc[i, "SectionMaxEntropy"] = max(section_entropy_dict.values())
        
        section_raw_size_dict = {}
        for section in pe.sections:
            section_name = section.Name.decode('utf-8').strip('\x00')
            raw_size = section.SizeOfRawData
            section_raw_size_dict[section_name] = raw_size

        df.loc[i, "SectionMinRawsize"] = min(section_raw_size_dict.values())
        df.loc[i, "SectionMaxRawsize"] = max(section_raw_size_dict.values())
        
        section_virt_size_dict = {}
        for section in pe.sections:
            section_name = section.Name.decode('utf-8').strip('\x00')
            virt_size = section.Misc_VirtualSize
            section_virt_size_dict[section_name] = virt_size
            
        df.loc[i, "SectionMinVirtualsize"] = min(section_virt_size_dict.values())
        df.loc[i, "SectionMaxVirtualsize"] = max(section_virt_size_dict.values())
        
        section_physical_addr_dict = {}
        for section in pe.sections:
            section_name = section.Name.decode('utf-8').strip('\x00')
            physical = section.Misc_PhysicalAddress
            section_physical_addr_dict[section_name] = physical
            
        df.loc[i, "SectionMaxPhysical"] = max(section_physical_addr_dict.values())
        df.loc[i, "SectionMinPhysical"] = min(section_physical_addr_dict.values())
        
        section_virt_addr_dict = {}
        for section in pe.sections:
            section_name = section.Name.decode('utf-8').strip('\x00')
            virtual = section.VirtualAddress
            section_virt_addr_dict[section_name] = virtual
    
        df.loc[i, "SectionMaxVirtual"] = max(section_virt_addr_dict.values())
        df.loc[i, "SectionMinVirtual"] = min(section_virt_addr_dict.values())
        
        section_pointer_data_dict = {}
        for section in pe.sections:
            section_name = section.Name.decode('utf-8').strip('\x00')
            pointer_data = section.PointerToRawData
            section_pointer_data_dict[section_name] = pointer_data
            
        df.loc[i, "SectionMaxPointerData"] = max(section_pointer_data_dict.values())
        df.loc[i, "SectionMinPointerData"] = min(section_pointer_data_dict.values())

        section_char_dict = {}
        for section in pe.sections:
            section_name = section.Name.decode('utf-8').strip('\x00')
            chars = section.Characteristics
            section_char_dict[section_name] = chars
            
        df.loc[i, "SectionMaxChar"] = max(section_char_dict.values())
        df.loc[i, "SectionMainChar"] = min(section_char_dict.values())
        
        try:
            df.loc[i, "DirectoryEntryImport"] = len(pe.DIRECTORY_ENTRY_IMPORT)
        except:
            df.loc[i, "DirectoryEntryImport"] = 0
        try:
            df.loc[i, "DirectoryEntryExport"] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
        except:
            df.loc[i, "DirectoryEntryExport"] = 0
        
        df.loc[i, "ImageDirectoryEntryExport"] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']].Size
        df.loc[i, "ImageDirectoryEntryImport"] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].Size
        df.loc[i, "ImageDirectoryEntryResource"] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']].Size
        df.loc[i, "ImageDirectoryEntryException"] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXCEPTION']].Size
        df.loc[i, "ImageDirectoryEntrySecurity"] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size
        pe.close()
    return df
rs = pickle.load(open("rs.pkl", "rb"))
drop_cols = [
    'Name', 'e_magic', 'SectionMaxEntropy', 'SectionMaxRawsize', 'SectionMaxVirtualsize', 'SectionMinPhysical', 'SectionMinVirtual', 
    'SectionMinPointerData', 'SectionMainChar'
]
def test_file(file_path, features, drop_cols):
    test_df = pd.DataFrame({"Name": [file_path]})
    result_df = analyze(test_df)
    test_df = result_df.drop(drop_cols, axis=1)
    test = rs.transform(test_df)
    test = pd.DataFrame(test, columns=test_df.columns)
    test = test[features]
    result = best_model.predict_proba(test)
    if np.argmax(result) == 1:
        print("[+] This file is malicious.")
        return "malicious"
    else:
        print("[+] This file is clean.")
        return "safe"
        

def extract_embedded_exe(image_path, output_exe_path="extracted.exe"):
    try:
        with open(image_path, "rb") as img_file:
            img_data = img_file.read()
        
        mz_index = img_data.find(b'MZ')
        if mz_index == -1:
            
            print("[+] No embedded EXE found.")
            return None
        
        exe_data = img_data[mz_index:]
        
        with open(output_exe_path, "wb") as exe_file:
            exe_file.write(exe_data)
        
        print(f"[+] Extracted EXE saved as: {output_exe_path}")
        return output_exe_path
    except Exception as e:
        print(f"[Error] {e}")
        return None

    
app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route("/check", methods=["POST"])
def check():
    try:
        image = request.files.get("image")
        if not image:
            return jsonify(status="error", message="No image uploaded"), 400

        filename = secure_filename(image.filename)
        image_path = os.path.join(UPLOAD_FOLDER, filename)
        image.save(image_path)
        print(f"[INFO] File saved to {image_path}")

        if os.path.exists("./extracted.exe"):
            os.remove("./extracted.exe")

        exe_path = extract_embedded_exe(image_path)
        if not exe_path:
            print("[INFO] No EXE found in image.")
            return jsonify(status="safe", message="No EXE embedded")

        result = test_file(exe_path, features, drop_cols)
        print(f"[INFO] Scan result: {result}")
        
        # Ensure file is deleted after scanning
        try:
            os.remove(exe_path)
            print(f"[INFO] Extracted EXE file {exe_path} removed successfully.")
        except Exception as e:
            print(f"[WARNING] Failed to remove extracted EXE file: {e}")

        return jsonify(status=result)
    except Exception as e:
        print(f"[FATAL ERROR]: {e}")
        return jsonify(status="error", message="Internal error"), 500

if __name__ == "__main__":
    app.run(debug=True)
