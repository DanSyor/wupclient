# may or may not be inspired by plutoo's ctrrpc
from __future__ import print_function
import errno    
import socket
import os
import sys
import struct
from time import sleep
import xml.etree.ElementTree as ET
import binascii
import ftplib
from ip import asknconfirmIP

PY2 = sys.version_info[0] == 2
PY3 = sys.version_info[0] == 3
if PY2:
    input = raw_input
    from StringIO import StringIO as BytesIO
else:
    from io import BytesIO

def buffer(size):
    return bytearray([0x00] * size)

def copy_string(buffer, s, offset):
    s += "\0"
    buffer[offset : (offset + len(s))] = bytearray(s, "ascii")

def copy_word(buffer, w, offset):
    buffer[offset : (offset + 4)] = struct.pack(">I", w)

def get_string(buffer, offset):
    s = buffer[offset:]
    if b'\x00' in s:
        return s[:s.index(b'\x00')].decode("utf-8")
    else:
        return s.decode("utf-8")

class wupclient:
    s=None

    def __init__(self, ip='192.168.1.91', port=1337):
        self.s=socket.socket()
        self.s.connect((ip, port))
        self.fsa_handle = None
        self.cwd = "/vol/storage_mlc01"
        
        self.ip = ip
        self.ftp = None
        
        # self.mountpoints = ["/vol/storage_mlc01","/vol/system","/vol/system_slc01"]
        self.mount_table = {"/dev/mlc01": ["/vol/storage_mlc01"], "/dev/slc01": ["/vol/system", "/vol/system_slc"], "/dev/slccmpt01": [],
                            "/dev/usb01": ["/vol/storage_usb01"], "/dev/sdcard01": [], "/dev/odd01": [], "/dev/odd02": [], "/dev/odd03": [], "/dev/odd04": []}

    def __del__(self):
        if self.fsa_handle != None:
            self.close(self.fsa_handle)
            self.fsa_handle = None
        if self.ftp:
            self.ftp.quit()
    
    def init_ftp(self):
        self.ftp = ftplib.FTP(self.ip)
        self.ftp.login()

    # fundamental comms
    def send(self, command, data):
        request = struct.pack('>I', command) + data

        self.s.send(request)
        response = self.s.recv(0x600)

        ret = struct.unpack(">I", response[:4])[0]
        return (ret, response[4:])
        
    
    def send_and_exit(self, command, data):
        request = struct.pack('>I', command) + data
        self.s.send(request)
        self.s.close()
        self.s = None
        self.fsa_handle = None
        exit()

    # core commands
    def read(self, addr, len):
        data = struct.pack(">II", addr, len)
        ret, data = self.send(1, data)
        if ret == 0:
            return data
        else:
            print("read error : %08X" % ret)
            return None

    def write(self, addr, data):
        data = struct.pack(">I", addr) + data
        ret, data = self.send(0, data)
        if ret == 0:
            return ret
        else:
            print("write error : %08X" % ret)
            return None

    def svc(self, svc_id, arguments):
        data = struct.pack(">I", svc_id)
        for a in arguments:
            data += struct.pack(">I", a)
        ret, data = self.send(2, data)
        if ret == 0:
            return struct.unpack(">I", data)[0]
        else:
            print("svc error : %08X" % ret)
            return None
    
    def svc_and_exit(self, svc_id, arguments):
        data = struct.pack(">I", svc_id)
        for a in arguments:
            data += struct.pack(">I", a)
        self.send_and_exit(2, data)

    def kill(self):
        ret, _ = self.send(3, bytearray())
        return ret

    def memcpy(self, dst, src, len):
        data = struct.pack(">III", dst, src, len)
        ret, data = self.send(4, data)
        if ret == 0:
            return ret
        else:
            print("memcpy error : %08X" % ret)
            return None

    def repeatwrite(self, dst, val, n):
        data = struct.pack(">III", dst, val, n)
        ret, data = self.send(5, data)
        if ret == 0:
            return ret
        else:
            print("repeatwrite error : %08X" % ret)
            return None

    # derivatives
    def alloc(self, size, align = None):
        if size == 0:
            return 0
        if align == None:
            return self.svc(0x27, [0xCAFF, size])
        else:
            return self.svc(0x28, [0xCAFF, size, align])

    def free(self, address):
        if address == 0:
            return 0
        return self.svc(0x29, [0xCAFF, address])

    def load_buffer(self, b, align = None):
        if len(b) == 0:
            return 0
        address = self.alloc(len(b), align)
        self.write(address, b)
        return address

    def load_string(self, s, align = None):
        return self.load_buffer(bytearray(s + "\0", "ascii"), align)

    def open(self, device, mode):
        address = self.load_string(device)
        handle = self.svc(0x33, [address, mode])
        self.free(address)
        return handle

    def close(self, handle):
        return self.svc(0x34, [handle])

    def ioctl(self, handle, cmd, inbuf, outbuf_size):
        in_address = self.load_buffer(inbuf)
        out_data = None
        if outbuf_size > 0:
            out_address = self.alloc(outbuf_size)
            ret = self.svc(0x38, [handle, cmd, in_address, len(inbuf), out_address, outbuf_size])
            out_data = self.read(out_address, outbuf_size)
            self.free(out_address)
        else:
            ret = self.svc(0x38, [handle, cmd, in_address, len(inbuf), 0, 0])
        self.free(in_address)
        return (ret, out_data)

    def iovec(self, vecs):
        data = bytearray()
        for (a, s) in vecs:
            data += struct.pack(">III", a, s, 0)
        return self.load_buffer(data)

    def ioctlv(self, handle, cmd, inbufs, outbuf_sizes, inbufs_ptr = [], outbufs_ptr = []):
        inbufs = [(self.load_buffer(b, 0x40), len(b)) for b in inbufs]
        outbufs = [(self.alloc(s, 0x40), s) for s in outbuf_sizes]
        iovecs = self.iovec(inbufs + inbufs_ptr + outbufs_ptr + outbufs)
        out_data = []
        ret = self.svc(0x39, [handle, cmd, len(inbufs + inbufs_ptr), len(outbufs + outbufs_ptr), iovecs])
        for (a, s) in outbufs:
            out_data += [self.read(a, s)]
        for (a, _) in (inbufs + outbufs):
            self.free(a)
        self.free(iovecs)
        return (ret, out_data)

    # fsa
    def FSA_Mount(self, handle, device_path, volume_path, flags):
        inbuffer = buffer(0x520)
        copy_string(inbuffer, device_path, 0x0004)
        copy_string(inbuffer, volume_path, 0x0284)
        copy_word(inbuffer, flags, 0x0504)
        (ret, _) = self.ioctlv(handle, 0x01, [inbuffer, bytearray()], [0x293])
        # self.mountpoints.append(volume_path)
        if not device_path in self.mount_table.keys():
            self.mount_table[device_path] = [volume_path]
        else:
            self.mount_table[device_path].append(volume_path)
        return ret

    def FSA_Unmount(self, handle, path, flags):
        inbuffer = buffer(0x520)
        copy_string(inbuffer, path, 0x4)
        copy_word(inbuffer, flags, 0x284)
        (ret, _) = self.ioctl(handle, 0x02, inbuffer, 0x293)
        # self.mountpoints.remove(path)
        for device, volumes in self.mount_table.items():
            if path in volumes:
                volumes.remove(path)
        return ret

    def FSA_RawOpen(self, handle, device):
        inbuffer = buffer(0x520)
        copy_string(inbuffer, device, 0x4)
        (ret, data) = self.ioctl(handle, 0x6A, inbuffer, 0x293)
        return (ret, struct.unpack(">I", data[4:8])[0])

    def FSA_OpenDir(self, handle, path):
        inbuffer = buffer(0x520)
        copy_string(inbuffer, path, 0x4)
        (ret, data) = self.ioctl(handle, 0x0A, inbuffer, 0x293)
        return (ret, struct.unpack(">I", data[4:8])[0])

    def FSA_ReadDir(self, handle, dir_handle):
        inbuffer = buffer(0x520)
        copy_word(inbuffer, dir_handle, 0x4)
        (ret, data) = self.ioctl(handle, 0x0B, inbuffer, 0x293)
        data = bytearray(data[4:])
        unk = data[:0x64]
        if ret == 0:
            # return (ret, {"name" : get_string(data, 0x64), "is_file" : (ord(unk[0]) & 128) != 128, "unk" : unk})
            return (ret, {"name" : get_string(data, 0x64), "is_file" : (unk[0] & 128) != 128, "unk" : unk})
        else:
            return (ret, None)

    def FSA_CloseDir(self, handle, dir_handle):
        inbuffer = buffer(0x520)
        copy_word(inbuffer, dir_handle, 0x4)
        (ret, data) = self.ioctl(handle, 0x0D, inbuffer, 0x293)
        return ret

    def FSA_OpenFile(self, handle, path, mode):
        inbuffer = buffer(0x520)
        copy_string(inbuffer, path, 0x4)
        copy_string(inbuffer, mode, 0x284)
        (ret, data) = self.ioctl(handle, 0x0E, inbuffer, 0x293)
        return (ret, struct.unpack(">I", data[4:8])[0])

    def FSA_MakeDir(self, handle, path, flags):
        inbuffer = buffer(0x520)
        copy_string(inbuffer, path, 0x4)
        copy_word(inbuffer, flags, 0x284)
        (ret, _) = self.ioctl(handle, 0x07, inbuffer, 0x293)
        return ret

    def FSA_ReadFile(self, handle, file_handle, size, cnt):
        inbuffer = buffer(0x520)
        copy_word(inbuffer, size, 0x08)
        copy_word(inbuffer, cnt, 0x0C)
        copy_word(inbuffer, file_handle, 0x14)
        (ret, data) = self.ioctlv(handle, 0x0F, [inbuffer], [size * cnt, 0x293])
        return (ret, data[0])

    def FSA_WriteFile(self, handle, file_handle, data):
        inbuffer = buffer(0x520)
        copy_word(inbuffer, 1, 0x08) # size
        copy_word(inbuffer, len(data), 0x0C) # cnt
        copy_word(inbuffer, file_handle, 0x14)
        (ret, data) = self.ioctlv(handle, 0x10, [inbuffer, data], [0x293])
        return (ret)

    def FSA_ReadFilePtr(self, handle, file_handle, size, cnt, ptr):
        inbuffer = buffer(0x520)
        copy_word(inbuffer, size, 0x08)
        copy_word(inbuffer, cnt, 0x0C)
        copy_word(inbuffer, file_handle, 0x14)
        (ret, data) = self.ioctlv(handle, 0x0F, [inbuffer], [0x293], [], [(ptr, size*cnt)])
        return (ret, data[0])

    def FSA_Remove(self, handle, path):
        inbuffer = buffer(0x520)
        copy_string(inbuffer, path, 0x04)
        (ret, _) = self.ioctl(handle, 0x08, inbuffer, 0x293)
        return ret

    def FSA_WriteFilePtr(self, handle, file_handle, size, cnt, ptr):
        inbuffer = buffer(0x520)
        copy_word(inbuffer, size, 0x08)
        copy_word(inbuffer, cnt, 0x0C)
        copy_word(inbuffer, file_handle, 0x14)
        (ret, data) = self.ioctlv(handle, 0x10, [inbuffer], [0x293], [(ptr, size*cnt)], [])
        return (ret)

    def FSA_GetStatFile(self, handle, file_handle):
        inbuffer = buffer(0x520)
        copy_word(inbuffer, file_handle, 0x4)
        (ret, data) = self.ioctl(handle, 0x14, inbuffer, 0x64)
        return (ret, struct.unpack(">IIIIIIIIIIIIIIIIIIIIIIIII", data))

    def FSA_CloseFile(self, handle, file_handle):
        inbuffer = buffer(0x520)
        copy_word(inbuffer, file_handle, 0x4)
        (ret, data) = self.ioctl(handle, 0x15, inbuffer, 0x293)
        return ret

    def FSA_ChangeMode(self, handle, path, mode):
        mask = 0x777
        inbuffer = buffer(0x520)
        copy_string(inbuffer, path, 0x0004)
        copy_word(inbuffer, mode, 0x0284)
        copy_word(inbuffer, mask, 0x0288)
        (ret, _) = self.ioctl(handle, 0x20, inbuffer, 0x293)
        return ret

    # mcp
    def MCP_InstallGetInfo(self, handle, path):
        inbuffer = buffer(0x27F)
        copy_string(inbuffer, path, 0x0)
        (ret, data) = self.ioctlv(handle, 0x80, [inbuffer], [0x16])
        return (ret, struct.unpack(">IIIIIH", data[0]))

    def MCP_Install(self, handle, path):
        inbuffer = buffer(0x27F)
        copy_string(inbuffer, path, 0x0)
        (ret, _) = self.ioctlv(handle, 0x81, [inbuffer], [])
        return ret

    def MCP_InstallGetProgress(self, handle):
        (ret, data) = self.ioctl(handle, 0x82, [], 0x24)
        return (ret, struct.unpack(">IIIIIIIII", data))

    def MCP_CopyTitle(self, handle, path, dst_device_id, flush):
        inbuffer = buffer(0x27F)
        copy_string(inbuffer, path, 0x0)
        inbuffer2 = buffer(0x4)
        copy_word(inbuffer2, dst_device_id, 0x0)
        inbuffer3 = buffer(0x4)
        copy_word(inbuffer3, flush, 0x0)
        (ret, _) = self.ioctlv(handle, 0x85, [inbuffer, inbuffer2, inbuffer3], [])
        return ret

    def MCP_InstallSetTargetDevice(self, handle, device):
        inbuffer = buffer(0x4)
        copy_word(inbuffer, device, 0x0)
        (ret, _) = self.ioctl(handle, 0x8D, inbuffer, 0)
        return ret

    def MCP_InstallSetTargetUsb(self, handle, device):
        inbuffer = buffer(0x4)
        copy_word(inbuffer, device, 0x0)
        (ret, _) = self.ioctl(handle, 0xF1, inbuffer, 0)
        return ret

    # syslog (tmp)
    def dump_syslog(self):
        syslog_address = struct.unpack(">I", self.read(0x05095ECC, 4))[0] + 0x10
        block_size = 0x400
        for i in range(0, 0x40000, block_size):
            data = self.read(syslog_address + i, 0x400)
            # if 0 in data:
            #     print(data[:data.index(0)].decode("ascii"))
            #     break
            # else:
            print(data.decode("ascii"))

    # file management
    def get_fsa_handle(self):
        if self.fsa_handle == None:
            self.fsa_handle = self.open("/dev/fsa", 0)
        return self.fsa_handle

    def mkdir(self, path, flags):
        fsa_handle = self.get_fsa_handle()
        if path[0] != "/":
            path = self.cwd + "/" + path
        ret = w.FSA_MakeDir(fsa_handle, path, flags)
        if ret == 0:
            return 0
        else:
            print("mkdir error (%s, %08X)" % (path, ret))
            return ret

    def chmod(self, filename, flags):
        fsa_handle = self.get_fsa_handle()
        if filename[0] != "/":
            filename = self.cwd + "/" + filename
        ret = w.FSA_ChangeMode(fsa_handle, filename, flags)
        print("chmod returned : " + hex(ret))
        
    def cd(self, path):
        if path[0] != "/" and self.cwd[0] == "/":
            return self.cd(self.cwd + "/" + path)
        fsa_handle = self.get_fsa_handle()
        ret, dir_handle = self.FSA_OpenDir(fsa_handle, path if path != None else self.cwd)
        if ret == 0:
            self.cwd = path
            self.FSA_CloseDir(fsa_handle, dir_handle)
            return 0
        else:
            print("cd error : path does not exist (%s)" % (path))
            return -1

    def ftpnorm(self,path):
        if not path:
            path = self.cwd
        if path[0] != "/":
            path = self.cwd + "/" + path
        if path.startswith("/vol"):
            path = path.replace("/vol/",               "/"
                      ).replace("/storage_mlc01/",     "/storage_mlc/"
                      ).replace("/system/",            "/storage_slc/"
                      ).replace("/system_slc/",        "/storage_slc/"
                      ).replace("/storage_slccmpt01/", "/slccmpt01/"
                      ).replace("/storage_usb01/",     "/storage_usb/"
                      ).replace("/storage_sdcard/",    "/sd/")
        return path
            
    def ls(self, path = None, return_data = False, silent = False):
        if path != None and path[0] != "/":
            path = self.cwd + "/" + path
        if path and path[-1] == "/":
            path = path[:-1]
        fsa_handle = self.get_fsa_handle()
        ret, dir_handle = self.FSA_OpenDir(fsa_handle, path if path != None else self.cwd)
        if ret != 0x0:
            if not silent:
                print("opendir error : " + hex(ret))
            return [] if return_data else None
        entries = []
        while True:
            ret, data = self.FSA_ReadDir(fsa_handle, dir_handle)
            if ret != 0:
                break
            if not(return_data):
                if data["is_file"]:
                    print("     %s" % data["name"])
                else:
                    print("     %s/" % data["name"])
            else:
                entries += [data]
        ret = self.FSA_CloseDir(fsa_handle, dir_handle)
        return entries if return_data else None
    
    def ls_names(self,path):
        entries = []
        for e in self.ls(path,True,True):
            entries.append(e["name"])
        return entries
    
    def ls_dirs(self,path):
        entries = []
        for e in self.ls(path,True,True):
            if not e["is_file"]:
                entries.append(e["name"])
        return entries
    
    def ls_files(self,path):
        entries = []
        for e in self.ls(path,True,True):
            if e["is_file"]:
                entries.append(e["name"])
        return entries
    
    def ls_names_ftp(self,path):
        return self.ftp.nlst(self.ftpnorm(path))
    
    def ls_names_opti(self,path):
        if self.ftp:
            return self.ls_names_ftp(path)
        else:
            return self.ls_names(path)

    def dldir(self, path):
        if path[0] != "/":
            path = self.cwd + "/" + path
        entries = self.ls(path, True)
        for e in entries:
            if e["is_file"]:
                print(e["name"])
                self.dl(path + "/" + e["name"],path[1:])
            else:
                print(e["name"] + "/")
                self.dldir(path + "/" + e["name"])
    
    def cpdir(self, srcpath, dstpath):
        entries = self.ls(srcpath, True)
        q = [(srcpath, dstpath, e) for e in entries]
        while len(q) > 0:
            _srcpath, _dstpath, e = q.pop()
            _srcpath += "/" + e["name"]
            _dstpath += "/" + e["name"]
            if e["is_file"]:
                print(e["name"])
                self.cp(_srcpath, _dstpath)
            else:
                self.mkdir(_dstpath, 0x600)
                entries = self.ls(_srcpath, True)
                q += [(_srcpath, _dstpath, e) for e in entries]

    def pwd(self):
        return self.cwd

    def cp(self, filename_in, filename_out):
        fsa_handle = self.get_fsa_handle()
        if filename_in[0] != "/":
            filename_in = self.cwd + "/" + filename_in
        if filename_out[0] != "/":
            filename_out = self.cwd + "/" + filename_out
        if filename_out[-1] == "/":
            filename_out += filename_in.split("/")[-1]
        ret, in_file_handle = self.FSA_OpenFile(fsa_handle, filename_in, "r")
        if ret != 0x0:
            print("cp error : could not open " + filename_in)
            return
        ret, out_file_handle = self.FSA_OpenFile(fsa_handle, filename_out, "w")
        if ret != 0x0:
            print("cp error : could not open " + filename_out)
            return
        block_size = 0x10000
        buffer = self.alloc(block_size, 0x40)
        k = 0
        while True:
            ret, _ = self.FSA_ReadFilePtr(fsa_handle, in_file_handle, 0x1, block_size, buffer)
            k += ret
            ret = self.FSA_WriteFilePtr(fsa_handle, out_file_handle, 0x1, ret, buffer)
            sys.stdout.write(hex(k) + "\r"); sys.stdout.flush();
            if ret < block_size:
                break
        self.free(buffer)
        ret = self.FSA_CloseFile(fsa_handle, out_file_handle)
        ret = self.FSA_CloseFile(fsa_handle, in_file_handle)

    def df(self, filename_out, src, size):
        fsa_handle = self.get_fsa_handle()
        ret, out_file_handle = self.FSA_OpenFile(fsa_handle, filename_out, "w")
        if ret != 0x0:
            print("df error : could not open " + filename_out)
            return
        block_size = 0x10000
        buffer = self.alloc(block_size, 0x40)
        k = 0
        while k < size:
            cur_size = min(size - k, block_size)
            self.memcpy(buffer, src + k, cur_size)
            k += cur_size
            ret = self.FSA_WriteFilePtr(fsa_handle, out_file_handle, 0x1, cur_size, buffer)
            sys.stdout.write(hex(k) + " (%f) " % (float(k * 100) / size) + "\r"); sys.stdout.flush();
        self.free(buffer)
        ret = self.FSA_CloseFile(fsa_handle, out_file_handle)

    def dl(self, filename, directorypath = None, local_filename = None):
        fsa_handle = self.get_fsa_handle()
        if filename[0] != "/":
            filename = self.cwd + "/" + filename
        if local_filename == None:
            if "/" in filename:
                local_filename = filename[[i for i, x in enumerate(filename) if x == "/"][-1]+1:]
            else:
                local_filename = filename
        ret, file_handle = self.FSA_OpenFile(fsa_handle, filename, "r")
        if ret != 0x0:
            print("dl error : could not open " + filename)
            return
        buffer = bytearray()
        block_size = 0x400
        while True:
            ret, data = self.FSA_ReadFile(fsa_handle, file_handle, 0x1, block_size)
            # print(hex(ret), data)
            buffer += data[:ret]
            sys.stdout.write(hex(len(buffer)) + "\r"); sys.stdout.flush();
            if ret < block_size:
                break
        ret = self.FSA_CloseFile(fsa_handle, file_handle)
        if directorypath == None:
            open(local_filename, "wb").write(buffer)
        else:
            dir_path = os.path.dirname(os.path.abspath(sys.argv[0])).replace('\\','/')
            fullpath = dir_path + "/" + directorypath + "/"
            fullpath = fullpath.replace("//","/")
            mkdir_p(fullpath)
            open(fullpath + local_filename, "wb").write(buffer) 
    
    # def readBytes(self,filename,locations=[]):
    def dl_buf(self,filename):
        # if not locations:
            # stats = self.stat(filename,True)
            # if not stats:
                # print("readBytes error : could not open " + filename)
                # return
            # locations = [(0,stats[5])]
        # stop_offset = 0
        # for offset,size in locations:
            # stop_offset = max(stop_offset,offset+size)
        fsa_handle = self.get_fsa_handle()
        if filename[0] != "/":
            filename = self.cwd + "/" + filename
        ret, file_handle = self.FSA_OpenFile(fsa_handle, filename, "r")
        if ret != 0x0:
            print("dl_buf error : could not open " + filename)
            return
        buffer = bytearray()
        block_size = 0x400
        # cur_offset = 0
        # while cur_offset < stop_offset:
        while True:
            ret, data = self.FSA_ReadFile(fsa_handle, file_handle, 0x1, block_size)
            buffer += data[:ret]
            sys.stdout.write(hex(len(buffer)) + "\r"); sys.stdout.flush();
            # cur_offset += ret
            if ret < block_size:
                break
        sys.stdout.write(" "*len(hex(len(buffer))) + "\r"); sys.stdout.flush();
        ret = self.FSA_CloseFile(fsa_handle, file_handle)
        # return [buffer[offset:offset+size] for offset,size in locations]
        return buffer
    
    def dl_buf_ftp(self,filename,block_size = 0x2000):
        data = bytearray()
        msg = self.ftp.retrbinary("RETR "+self.ftpnorm(filename), lambda chunk: data.extend(chunk), block_size)
        return data
    
    def dl_buf_opti(self,filename,block_size = 0x2000):
        if self.ftp:
            return self.dl_buf_ftp(filename,block_size)
        else:
            return self.dl_buf(filename)
        
    def readlines(self,filename):
        fsa_handle = self.get_fsa_handle()
        if filename[0] != "/":
            filename = self.cwd + "/" + filename
        ret, file_handle = self.FSA_OpenFile(fsa_handle, filename, "r")
        if ret != 0x0:
            print("readlines error : could not open " + filename)
            return
        buffer = bytearray()
        block_size = 0x400
        while True:
            ret, data = self.FSA_ReadFile(fsa_handle, file_handle, 0x1, block_size)
            buffer += data[:ret]
            sys.stdout.write(hex(len(buffer)) + "\r"); sys.stdout.flush();
            if ret < block_size:
                break
        ret = self.FSA_CloseFile(fsa_handle, file_handle)
        lines = []
        for line in buffer.split('\n'):
            lines.append(str(line)+'\n')
        return lines
    
    def cat(self,filename):
        # print(self.dl_buf_opti(filename).decode("utf-8"))
        print(self.dl_buf_opti(filename).decode(sys.stdout.encoding))

    def mkdir_p(path):
        try:
            os.makedirs(path)
        except OSError as exc:  # Python >2.5
            if exc.errno == errno.EEXIST and os.path.isdir(path):
                pass
            else:
                raise
            
    def fr(self, filename, offset, size):
        fsa_handle = self.get_fsa_handle()
        if filename[0] != "/":
            filename = self.cwd + "/" + filename
        ret, file_handle = self.FSA_OpenFile(fsa_handle, filename, "r")
        if ret != 0x0:
            print("fr error : could not open " + filename)
            return
        buffer = bytearray()
        block_size = 0x400
        while True:
            ret, data = self.FSA_ReadFile(fsa_handle, file_handle, 0x1, block_size if (block_size < size) else size)
            buffer += data[:ret]
            sys.stdout.write(hex(len(buffer)) + "\r"); sys.stdout.flush();
            if len(buffer) >= size:
                break
        ret = self.FSA_CloseFile(fsa_handle, file_handle)
        return buffer

    def fw(self, filename, offset, buffer):
        fsa_handle = self.get_fsa_handle()
        if filename[0] != "/":
            filename = self.cwd + "/" + filename
        ret, file_handle = self.FSA_OpenFile(fsa_handle, filename, "r+")
        if ret != 0x0:
            print("fw error : could not open " + filename)
            return
        block_size = 0x400
        k = 0
        while True:
            cur_size = min(len(buffer) - k, block_size)
            if cur_size <= 0:
                break
            sys.stdout.write(hex(k) + "\r"); sys.stdout.flush();
            ret = self.FSA_WriteFile(fsa_handle, file_handle, buffer[k:(k+cur_size)])
            k += cur_size
        ret = self.FSA_CloseFile(fsa_handle, file_handle)
    
    def isdir(self, path):
        fsa_handle = self.get_fsa_handle()
        if path[0] != "/":
            path = self.cwd + "/" + path
        if path[-1] == "/":
            path = path[:-1]
        ret_open, dir_handle = self.FSA_OpenDir(fsa_handle, path)
        if ret_open == 0:
            ret_close = self.FSA_CloseDir(fsa_handle, dir_handle)
        return ret_open == 0
    
    def isfile(self,filename):
        fsa_handle = self.get_fsa_handle()
        if filename[0] != "/":
            filename = self.cwd + "/" + filename
        ret_open, file_handle = self.FSA_OpenFile(fsa_handle, filename, "r")
        if ret_open == 0:
            ret_close = self.FSA_CloseFile(fsa_handle, file_handle)
        return ret_open == 0

    def exists(self, path):
        return self.isdir(path) or self.isfile(path)
    
    def stat(self, filename, return_data = False):
        fsa_handle = self.get_fsa_handle()
        if filename[0] != "/":
            filename = self.cwd + "/" + filename
        ret, file_handle = self.FSA_OpenFile(fsa_handle, filename, "r")
        if ret != 0x0:
            print("stat error : could not open " + filename)
            return
        (ret, stats) = self.FSA_GetStatFile(fsa_handle, file_handle)
        if ret != 0x0:
            print("stat error : " + hex(ret))
        elif not return_data:
            print("flags: " + hex(stats[1]))
            print("mode: " + hex(stats[2]))
            print("owner: " + hex(stats[3]))
            print("group: " + hex(stats[4]))
            print("size: " + hex(stats[5]))
        ret = self.FSA_CloseFile(fsa_handle, file_handle)
        return stats if return_data and ret == 0 else None
        
    def chmodR(self,path=None,flags=0x644):
        entries = self.ls(path, True)
        q = [(path, e) for e in entries]
        while q:
            _path, e = q.pop()
            _path += "/" + e["name"]
            if e["is_file"]:
                stats = self.stat(_path,True)
                if stats and stats[2] == stats[3] == stats[4] == 0:
                    self.chmod(_path,flags)
            else:
                entries = self.ls(_path, True)
                q += [(_path, e) for e in entries]

    def askyesno(self):
        yes = set(['yes', 'ye', 'y'])
        no = set(['no','n', ''])
        while True:
            choice = raw_input().lower()
            if choice in yes:
               return True
            elif choice in no:
               return False
            else:
               print("Please respond with 'y' or 'n'")

    def rm(self, filename):
        fsa_handle = self.get_fsa_handle()
        if filename[0] != "/":
            filename = self.cwd + "/" + filename
        ret, file_handle = self.FSA_OpenFile(fsa_handle, filename, "r")
        if ret != 0x0:
            print("rm error : could not open " + filename + " (" + hex(ret) + ")")
            return
        self.FSA_CloseFile(fsa_handle, file_handle)
        print("WARNING: REMOVING A FILE CAN BRICK YOUR CONSOLE, ARE YOU SURE (Y/N)?")
        if self.askyesno() == True:
            ret = self.FSA_Remove(fsa_handle, filename)
            print("rm : " + hex(ret))
        else:
            print("rm aborted")

    def rmdir(self, path):
        fsa_handle = self.get_fsa_handle()
        if path[0] != "/":
            path = self.cwd + "/" + path
        ret, dir_handle = self.FSA_OpenDir(fsa_handle, path)
        if ret != 0x0:
            print("rmdir error : could not open " + path + " (" + hex(ret) + ")")
            return
        self.FSA_CloseDir(fsa_handle, dir_handle)
        if len(self.ls(path, True)) != 0:
            print("rmdir error : directory not empty!")
            return
        print("WARNING: REMOVING A DIRECTORY CAN BRICK YOUR CONSOLE, ARE YOU SURE (Y/N)?")
        if self.askyesno() == True:
            ret = self.FSA_Remove(fsa_handle, path)
            print("rmdir : " + hex(ret))
        else:
            print("rmdir aborted")

    def up(self, local_filename, filename = None):
        fsa_handle = self.get_fsa_handle()
        if filename == None:
            if "/" in local_filename:
                filename = local_filename[[i for i, x in enumerate(local_filename) if x == "/"][-1]+1:]
            else:
                filename = local_filename
        if filename[0] != "/":
            filename = self.cwd + "/" + filename
        if filename[-1] == "/":
            filename += local_filename.split("/")[-1]
        f = open(local_filename, "rb")
        ret, file_handle = self.FSA_OpenFile(fsa_handle, filename, "w")
        if ret != 0x0:
            print("up error : could not open " + filename)
            return
        progress = 0
        block_size = 0x400
        while True:
            data = f.read(block_size)
            ret = self.FSA_WriteFile(fsa_handle, file_handle, data)
            progress += len(data)
            sys.stdout.write(hex(progress) + "\r"); sys.stdout.flush();
            if len(data) < block_size:
                break
        ret = self.FSA_CloseFile(fsa_handle, file_handle)
        
        

def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise

def mount(device,volume):
    handle = w.open("/dev/fsa", 0)
    print(hex(handle))

    ret = w.FSA_Mount(handle, device, volume, 2)
    print(hex(ret))

    ret = w.close(handle)
    print(hex(ret))

def unmount(volume):
    handle = w.open("/dev/fsa", 0)
    print(hex(handle))

    ret = w.FSA_Unmount(handle, volume, 2)
    print(hex(ret))

    ret = w.close(handle)
    print(hex(ret))

def print_mount_table():
    baselen = 0
    for device,volumes in w.mount_table.items():
        if volumes:
            baselen = max(baselen,len(device))
    for device,volumes in w.mount_table.items():
        device_specified = False
        for mountpoint in volumes:
            print(device," "*(baselen-len(device)+1),mountpoint)
            if not device_specified:
                device_specified = True
                device = " "*len(device)
        if not volumes:
            print(device," "*(baselen-len(device)+1),"[none]")

def mount_sd():
    handle = w.open("/dev/fsa", 0)
    print(hex(handle))

    ret = w.FSA_Mount(handle, "/dev/sdcard01", "/vol/storage_sdcard", 2)
    print(hex(ret))

    ret = w.close(handle)
    print(hex(ret))

def unmount_sd():
    handle = w.open("/dev/fsa", 0)
    print(hex(handle))

    ret = w.FSA_Unmount(handle, "/vol/storage_sdcard", 2)
    print(hex(ret))

    ret = w.close(handle)
    print(hex(ret))

def mount_odd_content():
    handle = w.open("/dev/fsa", 0)
    print(hex(handle))

    ret = w.FSA_Mount(handle, "/dev/odd03", "/vol/storage_odd_content", 2)
    print(hex(ret))

    ret = w.close(handle)
    print(hex(ret))

def unmount_odd_content():
    handle = w.open("/dev/fsa", 0)
    print(hex(handle))

    ret = w.FSA_Unmount(handle, "/vol/storage_odd_content", 2)
    print(hex(ret))

    ret = w.close(handle)
    print(hex(ret))

def mount_odd_content2():
    mount("/dev/odd04","/vol/storage_odd_content2")
def unmount_odd_content2():
    unmount("/vol/storage_odd_content2")
    
def mount_slccmpt01():
    handle = w.open("/dev/fsa", 0)
    print(hex(handle))

    mountret = w.FSA_Mount(handle, "/dev/slccmpt01", "/vol/storage_slccmpt01", 2)
    print(hex(mountret))

    ret = w.close(handle)
    print(hex(ret))
    return mountret

def unmount_slccmpt01():
    handle = w.open("/dev/fsa", 0)
    print(hex(handle))

    mountret = w.FSA_Unmount(handle, "/vol/storage_slccmpt01", 2)
    print(hex(mountret))

    ret = w.close(handle)
    print(hex(ret))
    return mountret

def mount_odd_update():
    handle = w.open("/dev/fsa", 0)
    print(hex(handle))

    ret = w.FSA_Mount(handle, "/dev/odd02", "/vol/storage_odd_update", 2)
    print(hex(ret))

    ret = w.close(handle)
    print(hex(ret))

def unmount_odd_update():
    handle = w.open("/dev/fsa", 0)
    print(hex(handle))

    ret = w.FSA_Unmount(handle, "/vol/storage_odd_update", 2)
    print(hex(ret))

    ret = w.close(handle)
    print(hex(ret))

def mount_odd_tickets():
    handle = w.open("/dev/fsa", 0)
    print(hex(handle))

    ret = w.FSA_Mount(handle, "/dev/odd01", "/vol/storage_odd_tickets", 2)
    print(hex(ret))

    ret = w.close(handle)
    print(hex(ret))

def unmount_odd_tickets():
    handle = w.open("/dev/fsa", 0)
    print(hex(handle))

    ret = w.FSA_Unmount(handle, "/vol/storage_odd_tickets", 2)
    print(hex(ret))

    ret = w.close(handle)
    print(hex(ret))

def titlepath(id):
    id = id.lower()
    high_id = id[:8] if len(id) == 16 else "00050000"
    low_id  = id[-8:]
    pathUSB    = "/vol/storage_usb01/usr/title/"+high_id+"/"+low_id
    if w.isdir(pathUSB):
        return pathUSB
    pathMLCusr = "/vol/storage_mlc01/usr/title/"+high_id+"/"+low_id
    if w.isdir(pathMLCusr):
        return pathMLCusr
    pathMLCsys = "/vol/storage_mlc01/sys/title/"+high_id+"/"+low_id
    if w.isdir(pathMLCsys):
        return pathMLCsys

def title_meta_attrib(id,l_attrib =[],return_data = False):
    path = titlepath(id)
    # value = "[metadata unavailable]"
    l_val = []
    meta = None
    if not path:
        # value = "[title not installed]"
        if return_data:
            return 1, path, meta, l_val
        else:
            # print(value)
            print("[title not installed")
            return
    metafp = path+"/meta/meta.xml"
    status = 2 # 0 = ok, 1 = not installed, 2 = no meta.xml, 3 = empty meta.xml
    if w.isfile(metafp):
        status = 3
        data = w.dl_buf_opti(metafp)
        if data:
            status = 0
            if PY2:
                meta = ET.fromstring(str(data))#.decode("utf-8"))
                # meta = ET.fromstring(data.decode("utf-8").encode(sys.getfilesystemencoding()))
            else:
                meta = ET.fromstring(data.decode("utf-8"))
            # meta = ET.fromstring(str(data.decode("utf-8")))
            # for field in meta.findall(attrib):
                # print(field.text)
            # value = meta.find(attrib).text
            for attrib in l_attrib:
                value = meta.find(attrib).text
                if return_data:
                    l_val.append(value)
                else:
                    print(attrib+": "+str(value))
    # if return_data:
        # return value
    return (status, path, meta, l_val) if return_data else None
    # else:
        # print(value)

all_langs = ["ja" ,
             "en" ,
             "fr" ,
             "de" ,
             "it" ,
             "es" ,
             "zhs",
             "ko" ,
             "nl" ,
             "pt" ,
             "ru" ,
             "zht"]
all_langs_names = ["Japanese",
                   "English",
                   "French",
                   "German",
                   "Italian",
                   "Spanish",
                   "Chinese Simple",
                   "Korean",
                   "Dutch",
                   "Portuguese",
                   "Russian",
                   "Chinese Traditional"]
usr_lang = None
def init_usr_lang():
    global usr_lang
    cafe_data = w.dl_buf("/vol/system/proc/prefs/cafe.xml")
    if PY2:
        cafe_et = ET.fromstring(str(cafe_data))
    else:
        cafe_et = ET.fromstring(cafe_data.decode("utf-8"))
    id_lang = int(cafe_et.find("language"))
    print("Detected user language: "+all_langs_names[id_lang])
    usr_lang = all_langs[id_lang]

def titlelongname(id,_lang="usr",return_data=False):
    lang = _lang
    if _lang == "usr":
        if not usr_lang:
            init_usr_lang()
        lang = usr_lang
    status, path, meta, name = title_meta_attrib(id,["longname_"+lang,"longname_en"],return_data)
    if return_data:
        if status == 1:
            return "[title not installed]"
        elif status == 2:
            return "[title with no metadata]"
        elif status == 3:
            return "[title with empty metadata]"
        else:
            return name[0] if name[0] else name[1] if _lang == "usr" else "[name not available]"
def titleshortname(id,lang="en", return_data = False):
    lang = _lang
    if _lang == "usr":
        if not usr_lang:
            init_usr_lang()
        lang = usr_lang
    status, path, meta, name = title_meta_attrib(id,["shortname_"+lang,"shortname_en"],return_data)
    if return_data:
        if status == 1:
            return "[title not installed]"
        elif status == 2:
            return "[title with no metadata]"
        elif status == 3:
            return "[title with empty metadata]"
        else:
            return name[0] if name[0] else name[1] if _lang == "usr" else "[name not available]"

def show_installed_titles(lang="en"):
    paths = {"USB titles": "/vol/storage_usb01/usr/title", "MLC titles (usr)": "/vol/storage_mlc01/usr/title", "MLC titles (sys)": "/vol/storage_mlc01/sys/title"}
    for section,path in paths.items():
        print(section)
        for high_id in w.ls_dirs(path):
            for low_id in w.ls_dirs(path+"/"+high_id):
                # print(high_id+low_id,ET.fromstring(w.dl_buf_opti("/vol/storage_usb01/usr/title/"+high_id+"/"+low_id+"/meta/meta.xml").decode("utf-8")).find("longname_"+lang).text.replace("\n","\n"+" "*17))
                meta = path+"/"+high_id+"/"+low_id+"/meta/meta.xml"
                if w.isfile(meta):
                    print(high_id+low_id,ET.fromstring(str(w.dl_buf_opti(meta))).find("longname_"+lang).text.replace("\n","\n"+" "*17))
                else:
                    print(high_id+low_id,"[no metadata available]")

def tikinfo(data):
    offset_glob = 0
    info = []
    while offset_glob < len(data):
        titleid  = binascii.hexlify(bytes(data[offset_glob+0x1dc:offset_glob+0x1dc+0x08])).decode("utf-8")
        titlekey = binascii.hexlify(bytes(data[offset_glob+0x1bf:offset_glob+0x1bf+0x10])).decode("utf-8")
        info.append((titleid,titlekey))
        # offset_loc = 0x1dc+0x08
        offset_loc = 0x2b8
        while offset_glob+offset_loc < len(data):
            if struct.unpack(b">I", data[offset_glob+offset_loc:offset_glob+offset_loc+4])[0] == 0x10004:
                break
            offset_loc += 4
        offset_glob += offset_loc
    return info

def scan_dir_for_tickets(path_start, lang="en", return_data = False):
    all_infos = {}
    widthPath = 25
    ldg_id = 0
    if not return_data:
        print("Path"+" "*(widthPath-4)+" | Title ID         | Title key"+" "*23 + " | Install path"+" "*(17-12)+" | Name")
    queue = [path_start]
    while queue:
        path = queue.pop()
        for e in w.ls(path, True, True):
            if not e["is_file"]:
                queue.append(path+"/"+e["name"])
            elif e["name"].endswith(".tik"):
                tikpath = path+"/"+e["name"]
                infos = tikinfo(w.dl_buf(tikpath))
                pathknown = False
                if len(tikpath) > widthPath:
                    tikpath = "..."+tikpath[3-widthPath:]
                else:
                    tikpath += " "*(widthPath-len(tikpath))
                for titleid,titlekey in infos:
                    if not return_data:
                        name = titlelongname(titleid, lang, True)
                        name = name.replace("\n","\n"+" "*(4+8+12+3+16+3+32+3+17+4)) if name else ""
                        installpath = titlepath(titleid)
                        installpath = installpath[5:22] if installpath else "Not installed    "
                        print(tikpath+" "*3+titleid + " "*3 + titlekey + " "*3 +installpath+ " "*3 + name)
                        if not pathknown:
                            pathknown = True
                            tikpath = " "*widthPath
                    else:
                        sys.stdout.write("["+"."*(9-abs(9-ldg_id)) + "|" + "."*(abs(9-ldg_id))+"]\r")
                        sys.stdout.flush()
                        ldg_id = (ldg_id + 1) % 18
                        high_id = titleid[:8]
                        low_id = titleid[8:]
                        if not low_id in all_infos.keys():
                            all_infos[low_id] = {}
                        all_infos[low_id][high_id] = titlekey
    sys.stdout.write(" "*12+"\r")
    sys.stdout.flush()
    return all_infos if return_data else None
                    

def scan_installed_tickets(lang="en", return_data = False):
    return scan_dir_for_tickets("/vol/system/rights/ticket/apps", lang, return_data)

def show_organized_ticket_data(tikinfos=None):
    if not tikinfos:
        tikinfos = scan_installed_tickets("",True)
    nTiks = 0
    for low_id, spec in tikinfos.items():
        # try:
        titlelongname("00050000"+high_id,"en")
        # sys.stdout.write(titlelongname("00050000"+high_id,"en",True)+"\n"); sys.stdout.flush();
        installpath = titlepath("00050000"+high_id)
        if installpath:
            print("\tinstalled to "+installpath[5:22])
            # sys.stdout.write("\tinstalled to "+installpath[5:22]+"\n"); sys.stdout.flush();
        for high_id,titlekey in spec.items():
            nTiks+=1
            print("\t\t"+high_id+low_id+" "+titlekey)
            # sys.stdout.write("\t\t"+low_id+high_id+" "+titlekey+"\n"); sys.stdout.flush()
        # except:
            # print(high_id+" breaks")
            # break
    print("Info for %i tickets" % nTiks)

def scan_sd_elf_img():
    elves = []
    imgs  = []
    sdroot = "/vol/storage_sdcard"
    queue = [sdroot]
    while queue:
        dir = queue.pop()
        for e in w.ls(dir,True,True):
            if not e["is_file"]:
                if input("scan "+(dir+"/")[20:]+e["name"]+"/? (Y/anything for no)").lower() == "y":
                    print((dir+"/")[20:]+e["name"]+"/ will be scanned")
                    queue.append(dir+"/"+e["name"])
            elif e["name"] == "fw.img":
                print((dir+"/")[20:]+u"fw.img")
                imgs.append((dir+"/")[20:]+u"fw.img")
            elif e["name"].endswith(".elf"):
                print((dir+"/")[20:]+e["name"])
                elves.append((dir+"/")[20:]+e["name"])
    return imgs, elves

def look4haxchititles():
    haxchititles_jpn = [("10179A00", "brainage",        ("","",""),     "Brain Age"),
                        ("10179D00", "yoshitouchandgo", ("","",""),     "Yoshi Touch & Go"),
                        ("10195600", "mariokartds",     ("","",""),     "Mario Kart DS"),
                        ("10195900", "newsmb",          ("","","_eur"), "New Super Mario Bros"),
                        ("10198800", "yoshids",         ("","",""),     "Yoshi's Island DS"),
                        ("101A1E00", "wwtouched",       ("","",""),     "WarioWare: Touched!"),
                        ("101A5500", "kirby",           ("","",""),     "Kirby Squeak Squad(Mouse Attack)"),
                        ("101AC000", "sfcommand",       ("","",""),     "Star Fox Command"),
                        ("101C3300", "sm64ds",          ("","",""),     "Super Mario 64 DS"),
                        ("101C3600", "zeldaph",         ("","",""),     "Zelda Phantom Hourglass")]
    haxchititles = []
    for id,zipname,zipext,name in haxchititles_jpn:
        haxchititles.append(("00050000"+id,name + " [JPN]",zipname+zipext[0]+".zip"))
        haxchititles.append(("00050000"+binascii.hexlify(struct.pack(b">I",0x100+struct.unpack(b">I",binascii.unhexlify(id))[0])).decode("utf-8"),name + " [NA]",zipname+zipext[1]+".zip"))
        haxchititles.append(("00050000"+binascii.hexlify(struct.pack(b">I",0x200+struct.unpack(b">I",binascii.unhexlify(id))[0])).decode("utf-8"),name + " [PAL]",zipname+zipext[2]+".zip"))
    print("Compatible titles you can find on the eShop:")
    for game in set([name[:name.rfind(" ")] for t,name,z in haxchititles]):
        print(" - "+ game)
    found = []
    compatible = []
    print("Checking if there's any compatible title installed...")
    for titleid,name,zipname in haxchititles:
        titleid = titleid.lower()
        installpath = titlepath(titleid)
        if installpath:
            print(name+" ("+titleid+") found at "+installpath)
            found.append(titleid)
            if w.isfile(installpath+"/content/0010/rom.zip"):
                print("Your version of "+name+" ("+titleid+") looks compatible for haxchi.")
                compatible.append((titleid, name, zipname, installpath))
            else:
                print("Unfortunately, your version of "+name+" ("+titleid+") doesn't look compatible. You should delete the game and download it again if you wish to use this game for the exploit.")
    if compatible:
        return compatible
    print("Checking if there's any (other) title that you already bought or got for free you could download again.")
    # return
    for low_id, spec in scan_installed_tickets("",True).items():
        for high_id in spec.keys():
            titleid = high_id+low_id
            for _titleid, name, zipname in haxchititles:
                # print(titleid+"|"+_titleid)
                if _titleid == titleid and not titleid in found:
                    found.append(titleid)
                    print("Ticket for "+name+" ("+titleid+") found, check the eShop!")
                    
    # for dir in w.ls("/vol/system/rights/ticket/apps",True):
        # dirname = dir["name"]
        # for ticket in w.ls("/vol/system/rights/ticket/apps/"+dirname,True):
            # tikname = ticket["name"]
            # sys.stdout.write("checking ticket in /vol/system/rights/ticket/apps/"+dirname+"/"+tikname+"\r"); sys.stdout.flush();
            # infos = tikinfo(w.dl_buf("/vol/system/rights/ticket/apps/"+dirname+"/"+tikname))
            # for _titleid,titlekey in infos:
                # for titleid,name in ids:
                    # titleid = titleid.lower()
                    # if len(titleid) == 8:
                        # titleid = "00050000"+titleid
                    # if _titleid == titleid:
                        # sys.stdout.write(" "*(50+4+1+12)+"\r"); sys.stdout.flush();
                        # print("Ticket for "+titleid+" ("+name+") found, check the eShop!")
                        # return
        
    # sys.stdout.write(" "*(50+4+1+12)+"\r"); sys.stdout.flush();
    return []

def install_title(path, installToUsb = 0):
    mcp_handle = w.open("/dev/mcp", 0)
    print(hex(mcp_handle))

    ret, data = w.MCP_InstallGetInfo(mcp_handle, "/vol/storage_sdcard/"+path)
    print("install info : " + hex(ret), [hex(v) for v in data])
    if ret != 0:
        ret = w.close(mcp_handle)
        print(hex(ret))
        return

    ret = w.MCP_InstallSetTargetDevice(mcp_handle, installToUsb)
    print("install set target device : " + hex(ret))
    if ret != 0:
        ret = w.close(mcp_handle)
        print(hex(ret))
        return

    ret = w.MCP_InstallSetTargetUsb(mcp_handle, installToUsb)
    print("install set target usb : " + hex(ret))
    if ret != 0:
        ret = w.close(mcp_handle)
        print(hex(ret))
        return

    ret = w.MCP_Install(mcp_handle, "/vol/storage_sdcard/"+path)
    print("install : " + hex(ret))

    ret = w.close(mcp_handle)
    print(hex(ret))

def copy_title(path, installToUsb = 0, flush = 0):
    mcp_handle = w.open("/dev/mcp", 0)
    print(hex(mcp_handle))

    ret = w.MCP_CopyTitle(mcp_handle, path, installToUsb, flush)
    print(hex(ret))

    ret = w.close(mcp_handle)
    print(hex(ret))

def get_nim_status():
    nim_handle = w.open("/dev/nim", 0)
    print(hex(nim_handle))
    
    inbuffer = buffer(0x80)
    (ret, data) = w.ioctlv(nim_handle, 0x00, [inbuffer], [0x80])

    print(hex(ret), "".join("%02X" % v for v in data[0]))

    ret = w.close(nim_handle)
    print(hex(ret))

def ios_shutdown():
    w.svc_and_exit(0x72,[0])
 
def ios_reset():
    w.svc_and_exit(0x72,[1])

def read_and_print(adr, size):
    data = w.read(adr, size)
    data = struct.unpack(">%dI" % (len(data) // 4), data)
    for i in range(0, len(data), 4):
        print(" ".join("%08X"%v for v in data[i:i+4]))

def read_and_dump(adr,size):
    f=open("dump.bin","wb")
    for i in range(0,size,1024):
        data = w.read(adr+i,1024)
        f.write(data)
    f.close()

if __name__ == '__main__':
    w = wupclient(asknconfirmIP())
    mount_sd()
    # mount_odd_content()
    
    # print(w.pwd())
    # w.ls()
    # w.dump_syslog()
    # w.mkdir("/vol/storage_sdcard/usr", 0x600)
    # install_title("test")
    # get_nim_status()
    # w.kill()
