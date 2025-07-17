import math 

def calculate_entropy(data):
    if not data:
        return 0.0
    
    frquency = [0]*256
    for byte in data:
        frquency[byte] += 1

    entropy = 0.0
    for count in frquency:
        if count == 0 :
            continue
        p = count /len(data)
        entropy -= p*math.log2(p)

    return entropy