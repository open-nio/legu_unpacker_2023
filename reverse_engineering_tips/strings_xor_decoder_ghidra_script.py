from java.io import File
from ghidra.app.util.exporter import CppExporter
from ghidra.util.task import TaskMonitor
from ghidra.app.util import Option
from ghidra.program.model.listing import Function
from ghidra.program.database.symbol import FunctionSymbol
import re
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.scalar import Scalar
from ghidra.program.model.data import StringDataType
from ghidra.program.model.data import Undefined

TMP_FILE_PATH="/tmp/stringfuncs.c"

def xor_decode(bytes, xor_value):
    print(bytes)
    buf=""
    for b in bytes:
      if b == 00:
        print("breaking at",b)
        break
      else:
        buf+= chr(b ^ xor_value)
    return buf  

program = getCurrentProgram()

function_manager = program.getFunctionManager()

# Loop through all the functions
for function in function_manager.getFunctions(True):  
    print(function)
    # Check if function name starts with "_INIT", which all the XOR decryptors do
    if function.getName().startswith("_INIT"):
        # Add a tag 'EXPORT' to it, which we will filter on later
        function.addTag('EXPORT')

# Create CppExporter and set options
exporter = CppExporter()
opts = [
    Option(CppExporter.FUNCTION_TAG_EXCLUDE, False),
    Option(CppExporter.FUNCTION_TAG_FILTERS, 'EXPORT') #filter on the tag we added earlier
]
exporter.setOptions(opts)
exporter.setExporterServiceProvider(state.getTool())

# Define export file and start exporting
f = File(TMP_FILE_PATH)
exporter.export(f, currentProgram, None, TaskMonitor.DUMMY)

# Define the regular expression
regex = r"((?:\(&DAT_(\w+)\)\[\w+\])|(?:\*\(byte \*\)\(\(int\)&DAT_(\w+) \+ \w+\))) = \1 \^ ((?:0x)?\w+);"

# Read the exported file and match regex looking for XOR encrypted strings
with open(TMP_FILE_PATH, "r") as f:
    exported = f.read()
    matches = re.finditer(regex, exported, re.MULTILINE)
    
    # Loop over all matches
    for matchNum, match in enumerate(matches, start=1):
        groups=match.groups()
        print(groups)
        address=groups[1] or groups[2]
        xor_value=groups[3]
        
        address = currentProgram.getAddressFactory().getAddress(address)
        if isinstance(xor_value,str):
            if "0x" in xor_value:
                xor_value = int(xor_value, 16)
            else:
                xor_value = int(xor_value)
        
        print("Processing address: {}, XOR value: {}".format(address, xor_value))

        clearListing(address)
        
        #sometimes the clearlisting doesn't work, so we just iterate through clearing bytes until the createAsciiString works
        created=None
        num_to_clear=0
        while not created:
            try:
                created=createAsciiString(address)
            except:
                num_to_clear+=1
                clearListing(address,address.add(num_to_clear))
        print ("value", created.value)

        enc_string=created.value.encode('utf-8')
        decoded_str = "".join([chr(ord(c) ^ xor_value) for c in enc_string])
        if "\x00" in decoded_str: #somehow we still get some null bytes here sometimes
            decoded_str=decoded_str[:decoded_str.index("\x00")]
        
        print("Decoded string: {}".format(decoded_str))

        clearListing(address,address.add(len(decoded_str)))
        print(decoded_str,type(decoded_str))
        label=decoded_str.replace(" ","_").replace("\n","\\n")
        createLabel(address, label , True)
        setPreComment(address,decoded_str)
        print("Created label '{}' at {}".format(decoded_str, address.toString()))