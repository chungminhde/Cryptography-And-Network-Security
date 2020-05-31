from tkinter import *
from tkinter.ttk import *
from Crypto.Cipher import AES
from Crypto.Cipher import DES3
from Crypto import Random
from Crypto.Hash import MD5
from Crypto.Hash import SHA256
from tkinter.filedialog import *
from tkinter import messagebox
import threading

import os, struct

class Assignment(Frame):
    def __init__(self, parent):
        Frame.__init__(self, parent)
        self.parent = parent
        self.chooseFile = ""
        self.chooseKey = ""
        self.out_file = ""
        self.chooFileDecrypt = ""
        self.chooseAl = StringVar()
        self.hashValue = ""

        self.initUI()
    
    def getKeyAES(self, password):
        return MD5.new(password.encode('utf-8')).digest()
    def getKey3DES(self, password):
        return SHA256.new(password.encode('utf-8')).digest()
    def readlineFile(self, file):
        f = open(file)
        line = f.readline()
        f.close()
        return line
#----------------Encrypt/Decrypt with AES algorithm------------------------------------------------------------
    def encryptionFileAES(self, progress, fileKey, inFileName, outFileName):
        chunksize = 64 * 1024
        
        password = self.readlineFile(self.chooseKey)
        key = self.getKeyAES(password)


        progressValue = 0
        progress["value"] = 0

        iv = Random.new().read(AES.block_size)
        encryptor = AES.new(key, AES.MODE_CBC, iv)
        filesize = os.path.getsize(inFileName)

        with open(inFileName, 'rb') as infile:
            with open(outFileName, 'wb') as outfile:
                outfile.write(struct.pack('<Q', filesize))
                outfile.write(iv)

                while True:
                    chunk = infile.read(chunksize)
                    if len(chunk) == 0:
                        break
                    elif len(chunk) % 16 != 0:
                        chunk += b' ' * (16 - len(chunk) % 16)
                    outfile.write(encryptor.encrypt(chunk))
                    progressValue += chunksize
                    progress["value"] = progressValue/filesize*100
                    

    def btnEncryption(self):
        self.out_file = self.chooseFile + ".enc"
        if (self.chooseAl.get() == 'AES'):
            threading._start_new_thread(self.encryptionFileAES, (self.progress, self.chooseKey, self.chooseFile, self.out_file))
        elif (self.chooseAl.get() == '3DES'):
            threading._start_new_thread(self.encryptionFile3DES, (self.progress, self.chooseKey, self.chooseFile, self.out_file))
        self.hashFileEncrypt = self.hashFile(self.chooseFile, self.progress)
        self.fileHashOriginal = self.chooseFile + "_hash.txt"
        with open(self.fileHashOriginal, 'w') as fileHash:
            fileHash.write(self.hashFileEncrypt)
    def decryptionFileAES(self, progress, filekey, inFileName, outFileName):
        chunksize = 64*1024
        filesize = os.path.getsize(inFileName)
        progressValue = 0
        progress["value"] = 0
        
        with open(inFileName, 'rb') as infile:
            origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
            iv = infile.read(AES.block_size)

            password = self.readlineFile(self.chooseKey)
            key = self.getKeyAES(password)
            decryptor = AES.new(key, AES.MODE_CBC, iv)

            with open(outFileName, 'wb') as outfile:
                while True:
                    chunk = infile.read(chunksize)
                    if len(chunk) == 0:
                        break
                    outfile.write(decryptor.decrypt(chunk))
                    progressValue += chunksize
                    progress["value"] = progressValue/filesize*100
                outfile.truncate(origsize)

    def btnDecryption(self):
        lengthName = len(os.path.basename(self.chooseFile))
        newName ="Decryption_"  + os.path.basename(self.chooseFile[:-4])
        self.out_file = self.chooseFile[:-lengthName] + newName
        if (self.chooseAl.get() == 'AES'):
            threading._start_new_thread(self.decryptionFileAES, (self.progress ,self.chooseKey, self.chooseFile, self.out_file))
        elif (self.chooseAl.get() == '3DES'):
            threading._start_new_thread(self.decryptionFile3DES, (self.progress, self.chooseKey, self.chooseFile, self.out_file))

#------------------Encrypt/Decrypt with 3DES Algorithm-----------------------
    def encryptionFile3DES(self, progress, fileKey, inFileName, outFileName):
        chunksize = 64*1024
        password = self.readlineFile(self.chooseKey)
        key = self.getKey3DES(password)[0:24]
        filesize = str(os.path.getsize(inFileName)).zfill(8)
        filesize_2 = os.path.getsize(inFileName) 

        progressValue = 0
        progress["value"] = 0

        iv = Random.get_random_bytes(8)
        encryptor = DES3.new(key, DES3.MODE_CFB, iv)

        with open(inFileName, 'rb') as inFile:
            with open(outFileName, 'wb') as outFile:
                outFile.write(filesize.encode('utf-8'))
                outFile.write(iv)

                while (True):
                    chunk = inFile.read(chunksize)
                    if len(chunk) == 0:
                        break
                    elif len(chunk) % 8 != 0:
                        chunk += b' '*(8-(chunk)%8)
                    outFile.write(encryptor.encrypt(chunk))
                    progressValue += chunksize
                    progress["value"] = progressValue/filesize_2*100

    def decryptionFile3DES(self, progress, keyFile, inFileName, outFileName):
        chunksize = 64*1024
        password = self.readlineFile(keyFile)
        key = self.getKey3DES(password)[0:24]
        
        progressValue = 0
        progress["value"] = 0
        filesize = os.path.getsize(inFileName)

        with open (inFileName, 'rb') as inFile:
            filesize = int(inFile.read(8))
            iv = inFile.read(8)
            decryptor = DES3.new(key, DES3.MODE_CFB, iv)
            with open (outFileName, 'wb') as outFile:
                while (True):
                    chunk = inFile.read(chunksize)
                    if(len(chunk) == 0):
                        break
                    outFile.write(decryptor.decrypt(chunk))
                    progressValue += chunksize
                    progress["value"] = progressValue/filesize*100

#-------------------Button Select(File and Key), Delete----------------------- 
    def btnSelectFile(self):
        fileName = askopenfilename()
        if fileName: 
            self.chooseFile = fileName
            self.nameFile.insert("1.0",os.path.basename(fileName))
        self.progressbarValue = 0
    def btnSelectKey(self):
        fileKey = askopenfilename()
        if fileKey:
            self.chooseKey = fileKey
            self.nameKey.insert("1.0", os.path.basename(fileKey))
    def btnDelete(self):
        self.nameFile.delete('1.0', END) 
        self.nameKey.delete('1.0', END)
        self.chooseKey = ""
        self.chooseFile = ""
        self.hashValue = ""
        self.chooseFileDecrypt = ""
        self.progress["value"] = 0
    def btnSelectFileHash(self):
        fileHash = askopenfilename()
        if fileHash:
            self.chooseFileHash = fileHash
            self.nameFile.insert('1.0',os.path.basename(fileHash))

#--------------------Hash File--------------------------------
    def hashFile(self, inFileName, progress):
        chunksize = 64*1024
        filesize = os.path.getsize(inFileName)
        hasher = MD5.new()
        progressValue = 0
        progress["value"] = 0
        with open(inFileName, 'rb') as inFile:
            chunk = inFile.read(chunksize)
            while len(chunk) > 0:
                hasher.update(chunk)
                chunk = inFile.read(chunksize)
                progressValue += chunksize
                progress["value"] = progressValue/filesize*100
        
        return hasher.hexdigest()
    def btnHash(self):
        outFile = self.chooseFileHash +"_hash.txt"
        threading._start_new_thread(self.hashFile,(self.chooseFileHash,self.progress))
        self.hashValue = self.hashFile(self.chooseFileHash,self.progress)
        with open(outFile, 'w') as fileHash:
            fileHash.write(self.hashValue)

#-----------------------------------UI----------------------------------------------        
    def initUI(self):
        self.parent.title("Encryption/Decryption File")
        self.Style = Style()
        self.Style.theme_use("default")
        Style().configure("TFrame",bg="#dcdcdc")
        
        frame1 = Frame(self, relief = FLAT, borderwidth = 1, bg = '#f5deb3')
        frame1.pack(fill = BOTH, expand = True)
        self.pack(fill = BOTH, expand = True)

        selectFileButton = Button(frame1, text = "Select File", command = self.btnSelectFile)
        selectFileButton.pack(side = LEFT, padx = 60, pady = 0)

       

        selectKeyButton = Button(frame1, text = "Select Key", command = self.btnSelectKey)
        selectKeyButton.pack(side = RIGHT, padx = 60, pady = 0)

        self.progress = Progressbar(frame1, length = 500, orient = HORIZONTAL, maximum = 100)
        self.progress.pack()

        labelAlgorithm = Label(frame1, text = 'Choose Algorithm:', bg = '#f5deb3')
        labelAlgorithm.pack(side = LEFT, fill = 'none')

        listAlgorithm = ['AES', '3DES']
        self.chooseAlgorithm = Radiobutton(frame1, text = 'AES', pady = 20, variable = self.chooseAl, value = 'AES', bg = '#f5deb3')
        self.chooseAlgorithm.pack()

        self.chooseAlgorithm = Radiobutton(frame1, text = '3DES', pady = 20, variable = self.chooseAl, value = '3DES',bg = '#f5deb3')
        self.chooseAlgorithm.pack()
        self.chooseAl.set('AES')

        frame2 = Frame(self, relief = RAISED, borderwidth = 2, bg = '#f5deb3')
        frame2.pack(fill = BOTH, expand = True)
        self.pack(fill = BOTH,  expand = True)

        selectFileButtonDecrpt = Button(frame2, text = "Select File to Hash", command = self.btnSelectFileHash)
        selectFileButtonDecrpt.pack(fill = 'none', padx = 60, pady = 0)
        
        encrypButton = Button(self, text = "Encryption", command = self.btnEncryption, bg = 'green')
        encrypButton.pack(side = LEFT, padx = 10, pady = 10)

        deleteButton = Button(frame2, text = 'Delete', command = self.btnDelete, bg = 'red' )
        deleteButton.pack(fill = 'none', pady =  40, side = BOTTOM )

        decrypButton = Button(self, text = "Decryption", command = self.btnDecryption, bg = 'green')
        decrypButton.pack(side = RIGHT, padx =10, pady = 10)

        integritiButton = Button(self, text  = 'Hash', command = self.btnHash,bg = 'yellow')
        integritiButton.pack(fill = 'none', pady = 10, padx = 10)

        self.nameFile = Text(frame2, bg = "white", height = 9, width = 14)
        self.nameFile.pack(side = LEFT, padx = 70 )
        
        self.nameKey = Text(frame2, bg = "white", height = 9, width = 14)
        self.nameKey.pack(side = RIGHT, padx = 70)
        
root = Tk()
root.configure(background = "#000000")
root.geometry("600x600+250+50")
app = Assignment(root)
root.mainloop()