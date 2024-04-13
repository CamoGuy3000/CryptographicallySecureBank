import random

def generate_random_binary_strings(min_length, max_length):
    # Determine the number of binary strings to generate
    list_length = random.randint(min_length, max_length)
    
    # Generate each binary string
    binary_strings = []
    for _ in range(list_length):
        # Generate a random binary string of length 8
        binary_string = ''.join(random.choice('01') for _ in range(8))
        binary_strings.append(binary_string)
    
    return binary_strings

# random_binary_strings = generate_random_binary_strings(5, 10)
# print(random_binary_strings)
