import pefile
pe = pefile.PE("a.out")

print hex(pe.VS_VERSIONINFO.Length)
print hex(pe.VS_VERSIONINFO.Type)
print hex(pe.VS_VERSIONINFO.ValueLength)
print hex(pe.VS_FIXEDFILEINFO.Signature)
print hex(pe.VS_FIXEDFILEINFO.FileFlags)
print hex(pe.VS_FIXEDFILEINFO.FileOS)
for fileinfo in pe.FileInfo:
  if fileinfo.Key == 'StringFileInfo':
    for st in fileinfo.StringTable:
      for entry in st.entries.items():
        print '%s: %s' % (entry[0], entry[1])    
  if fileinfo.Key == 'VarFileInfo':
    for var in fileinfo.Var:
      print '%s: %s' % var.entry.items()[0]
