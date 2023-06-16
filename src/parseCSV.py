with open("./data/topWebsites.csv", "r+") as f:
    lines = f.readlines()
    keep = []
    for line in lines:
        splitted = line.split(",")
        keep.append(splitted[1].strip().replace('"', ''))
    with open("./data/topWebsitesParsed.csv", "w") as file:
        for line in keep:
            file.write(f"{line}\n")
