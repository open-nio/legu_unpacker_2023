# How to hunt your own meat

I've extended the unpacker to include the new ChaCha encryption method as well as the key derivation algorithms used for both versions 20 and 31, but you may well come across a version not supported.

In this document, I wanted to share some tips for reversing engineering these for yourself.

## The basics

The binary that does the unpacking in Legu is at `lib/{arch}/libshell-super.2019.so` and usually comes in both 32 (`armeabi`) and 64 (`arm64-v8a`) bit versions.

All versions to date do a decryption using a key derived from a value stored in a file at `assets/tosversion`. This key is xored one or more times with various hardcoded values in the binary.

## Tools we'll be using:

* Ghidra: https://ghidra-sre.org/
* * control flow deflattening script: https://github.com/PAGalaxyLab/ghidra_scripts/blob/master/ollvm_deobf_fla.py

* BinDiff: http://www.zynamics.com/bindiff.html
* * Ghidra plugin: https://github.com/ubfx/BinDiffHelper

* Frida: https://github.com/frida/frida


## Basic techniques

There are two main techniques we can use to reverse engineer this, static and dynamic analysis.

### Static Analysis

We'll be using the FOSS decompiler Ghidra for this.

After importing, opening, and autoanalysing (turn on agressive instruction finding) the binary in Ghidra, the first step is to find the right functions.

This can be more difficult if starting from scratch, but an easier way is to run bindiff on the binary against a known version, and find the right functions that way.

You can find bindiff at http://www.zynamics.com/bindiff.html, and a Ghidra plugin at https://github.com/ubfx/BinDiffHelper

And I've included samples together with the important offsets to compare against at /reverse_engineering_tips/library_samples_for_bindiff/ of this repo.

#### Deobfuscating the deobfuscator

You'll notice a few obfuscations on the binary.

##### Xor Encoded Strings
Many strings in the later versions are xor encoded. These are decoded at load by functions with names starting with `_INIT_`.
I wrote a Ghidra script to decode those, though if it doesn't work you may need to tweak it for your code.

Once you've decoded the strings, you can look for strings such as "unpoison" to help you find your way to the decrypt methods.

##### Control flow flattening
This one is interesting. You can read more about it elsewhere but essentially this takes the whole complex flowchart of a function and reshapes it into a single-loop state-machine, which makes it harder to see what's happening. There's a good script to fix this at https://github.com/PAGalaxyLab/ghidra_scripts/blob/master/ollvm_deobf_fla.py, though it tends to work better on the 64-bit version (as there's more address space to insert jumps), and also it only works where there is a single state variable being used, rather than where there is a seperate read-to and write-to state variable. You use the script by positioning your cursor on top of an assignment to the state var and then running the script.




### Dynamic Analysis

For this it's probably easiest to use an Android emulator / virtual device, unless the real device you are working is rooted.

Download Android Studio and make a virtual device.
Use https://github.com/newbit1/rootAVD.git to root it, and then do a cold reboot of the device.

Then go to https://github.com/frida/frida/releases and download the latest frida-server with the right architecture and put it onto the device..

You might well be able to just dump the decrypted dex files with various scripts online, but assuming you want to actually reverse engineer the encryption, don't take that easy way out.

The key here is to write your own Frida scripts, using the knowledge you have from the decompiler, to test out various functions with your own inputs, and see what they return.

You'll first want to load the library

```
var moduleName = 'libshell-super.2019.so';
var module = Process.findModuleByName(moduleName);
```

Now for any memory address you want to read, or function you want to execute:

* First make sure you have the right architecture open in Ghidra
* Find the data or function you want
* Now, you'll need to figure out the right offset, Ghidra usually adds a 0x100000 to the offsets, so you'll want to subtract that off the Ghidra address each time
* Then you'll do
```
var offset = ptr(0xbeef);
var address = module.base.add(offset)
```

Now if it's data you want, you might be able to read it straight off from there with

```
  console.log(hexdump(address, {
        length: 0x20 
    }));
```

If it's a function, you'll need to define the function, based on its return type and variable types (broadly defined):

Suppose you have a function  `void decrypt(char* out, char* in, size_t len)`
Then you would define it as:
```
var decrypt_func = new NativeFunction(address, 'void', ['pointer', 'pointer', 'int']);
````

And then set up your buffers and call it
```
var out_buffer = Memory.alloc(0x20);
var in_buffer = Memory.allocUtf8String('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
var len = 0x20;

decrypt_func(out_buffer,in_buffer,len);
```
And then you can dump the outbuffer and see what it now contains:
```
console.log(hexdump(out_buffer, {
    length: 0x20
}));
```

So far, most of the key derivation functions have been xors of the value from `tosversion` (refered to in our script as the password), with some static value.
This value might be hardcoded directly, but may also be modified in the code itself; what you care about is the final value being xored by.

A very nice thing to do is to try and send the key derivation functions various data, then xor what comes out by what you put in, and see if there is a consistent result, in which case that's the value you need to xor against.

Be aware that in some places, a 32 byte key is being produced from the 16 byte password via xoring the password twice against two halves of one 32 byte value.

So to test for that you'll want to send the function a 32 byte buffer produced via repeating some 16 byte buffer (rather than sending it a unique 32 byte string), and then xor the result against what you sent it.

### Some hints as to what you are looking for:

### The top-level decrypt method

In versions up to 31, the basic encryption method looks something like this: 

(note that all function and variable names have been renamed by me for clarity)
```
void decrypt(byte *src,byte **out,size_t outlen)
{
  byte *pbVar1;
  char key [36];
  int local_24;
  
  //stack canary stuff
  pbVar1 = (byte *)calloc(1,outlen);
  *out = pbVar1;
  __aeabi_memclr8(key,0x20);
  static_key_copy(key,"^o0o7Ql]M8Y5:+1m~nTcA&3a7|?GB1z@",0x20);
  decrypt_inner(*out,src,outlen,key,"nzbnhgaf",0);
    //stach canary stuff
  return;
```

### static_key_copy

This method is very sneaky. It appears to be copying from the hardcoded middle parameter, but when you look carefully at the function code it actually ignores that dummy value completely, and just copies from a key set elsewhere. You may need to look at references to find where that data value is set, or do the dynamic analysis thing and just read it out.

### decrypt_inner

This method has alot of obfuscation applied, but it basically calls three other methods. One derives the final key we will use from the input key. That one should be examined carefully. Another one sets a nonce: don't think about that one too much (at least in current version, this could change), just grab that value as the nonce. And finally it calls a function that actually does the ChaCha decrypt. 

If you run into trouble, it could be worth validating with dynamic analysis that the ChaCha decrypt works as you'd expect. Just feed it some dummy values and keys and then process those yourself in python and make sure you come to the same answer. But if you do, then you can ignore that method.

Really the main function to focus on is the one that derives the final key.

After applying the control flow deflattening, and changing types, you may be left with a function that is essentially readable. Or you might need to do some dynamic analysis. Either way, you want to make sure you know how that one works.

### Wrapping up

Once you've determined the key derivation, the encryption method (presumably still ChaCha) and the nonce, you can add them to the script at `decryptors.py`.

You'll need to implement a Decryptor, which is most easily done by calling implementing methods for keyderive and decrypt (if necessary) and then calling Decryptor.from_decrypt_and_keyderive. You'll then add the version you implemented to `decryptors_by_version` and `decryptor_unknown_version`, following the examples already there. It should be pretty self-explanatory.

Congratulations! Don't forget to open a pull request with the new version you've cracked.