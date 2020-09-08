import sys
import os
from pathlib import Path
from hashlib import md5
from json import dump

try:
    import pefile
except ImportError:
    print('# Please install pefile (pip install pefile)')
    sys.exit(-1)

ALL_EXTENSIONS = (
    '.dll', '.acm', '.ax', '.cpl', '.drv', '.ocx'
)

def value_or_none(table, name):
    value = table.entries.get(name, None)
    if value:
        return value.decode('UTF-8')
    return None

def name_or_none(name):
    if name:
        return name.decode('UTF-8')
    return None

class PeInfo:
    def __init__(self, pe):
        self.CompanyName = None
        self.FileDescription = None
        self.FileVersion = None
        self.InternalName = None
        self.ProductVersion = None
        self._get_version(pe)
        arch = pefile.MACHINE_TYPE[pe.FILE_HEADER.Machine]
        self.arch = arch[len('IMAGE_FILE_MACHINE_'):]
        # Calculate the md5 from the (internal) raw data of the PE file
        hasher = md5()
        hasher.update(pe.__data__)
        self.md5sum = hasher.hexdigest()
        self.imphash = pe.get_imphash()
        self.CheckSum = pe.OPTIONAL_HEADER.CheckSum
        self.Size = len(pe.__data__)

    def _get_version(self, pe):
        for root in pe.FileInfo:
            for stringtables in [fileinfo.StringTable for fileinfo in root if fileinfo.Key == b'StringFileInfo']:
                for table in stringtables:
                    self.CompanyName = value_or_none(table, b'CompanyName')
                    self.FileDescription = value_or_none(table, b'FileDescription')
                    self.FileVersion = value_or_none(table, b'FileVersion')
                    self.InternalName = value_or_none(table, b'InternalName')
                    self.ProductVersion = value_or_none(table, b'ProductVersion')

    def as_json(self):
        obj = {
            'Version': '{}-{}'.format(self.ProductVersion, self.arch),
            'md5': self.md5sum,
            'imphash': self.md5sum,
            'InternalName': self.InternalName,
            'CompanyName': self.CompanyName,
            'FileDescription': self.FileDescription,
            'FileVersion': self.FileVersion,
            'ProductVersion': self.ProductVersion,
            'PeChecksum': self.CheckSum,
            'Size': self.Size,
            'Machine': self.arch
        }
        return obj

def grab_export(e):
    if (e.forwarder):
        return {'ordinal': e.ordinal, 'name': name_or_none(e.name), 'forwarder': name_or_none(e.forwarder)}
    return {'ordinal': e.ordinal, 'name': name_or_none(e.name)}


def dump_dlls(input_dir, output_dir, dll_list):
    dirs = [
            #pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']
        ]
    for dll in dll_list:
        dll_path = input_dir / dll
        if dll_path.is_file():
            try:
                pe = pefile.PE(dll_path, fast_load=True)
            except pefile.PEFormatError as pe_err:
                print(dll, ':', pe_err)
                continue
            pe.parse_data_directories(directories=dirs)
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                exports = [grab_export(e) for e in pe.DIRECTORY_ENTRY_EXPORT.symbols]
            else:
                exports = []
            info = PeInfo(pe)
            json = info.as_json()
            json['exports'] = exports
            filename = '{}.json'.format(dll)
            with open(output_dir / filename, 'w') as json_file:
                dump(json, json_file, indent='  ')
            #imports = []




def find_files(input_dir):
    for filename in os.listdir(input_dir):
        if filename.endswith(ALL_EXTENSIONS):
            yield filename

def main(args):
    if len(args) < 3 or '-?' in args or '/?' in args or '-h' in args or '/h' in args:
        print('Usage: dump_dll.py <input_directory> <output_directory> [filter]')
        print('      input_directory: Where to read dlls from')
        print('      output_directory: Where to write .json files to')
        print('      filter: Optional file with dlls to include (one per line)')
        return

    input_dir = args[1]
    output_dir = args[2]
    if len(args) > 3:
        with open(args[3], 'r') as input_filter:
            dll_list = [line.strip() for line in input_filter if line]
    else:
        dll_list = find_files(input_dir)
    dump_dlls(Path(input_dir), Path(output_dir), dll_list)


if __name__ == '__main__':
    main(sys.argv)
