import subprocess

originalOutputs = []
domainOutputs = []
filePath = "/home/koleslav/greycortex/domain_evaluation_mendel/src/domains.txt"

def writeResultsIntoFile(filename, results):
    with open(filename, "w") as f:
        for result in results:
            f.write(str(result))


with open(filePath, "r") as f:
    lines = (line.rstrip() for line in f) 
    lines = list(line for line in lines if line)
    for domain in lines:
        originalOutput = subprocess.check_output(['python3', '/home/koleslav/greycortex/original/domain_evaluation_mendel/src/init.py', domain, "--stdout"])
        print(originalOutput)
        originalOutputs.append(originalOutput)
print("[INFO] running mendel domain evaluation")
domainOutput = subprocess.check_output(['python3', '/home/koleslav/greycortex/domain_evaluation_mendel/src/init.py', domain])
print(domainOutput)
domainOutputs.append(originalOutput)
writeResultsIntoFile("original.txt", originalOutputs)
writeResultsIntoFile("mendel.txt", domainOutputs)
