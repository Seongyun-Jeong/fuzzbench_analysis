f = open("clonelist.txt",'r')
ff = open("clone.sh",'w')

lines = f.readlines()
for line in lines:
    line = line.split(" ")
    for i in line:
        if i[:5] == "https":
            tmp = "git clone " + i
            ff.write(tmp)
            ff.write("\n")