def read_bytes_from_file(file):
    file = open(file, 'r')
    byte_list = []
    for line in file:
        line = line.split()
        for bits in line:
            if len(bits) == 2:
                byte_list.append(int(bits, 16))
    return bytes(byte_list)
