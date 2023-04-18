import time
import os.path

CACHE_FILE = 'cache.txt'

# Load the cache data from the cache file, or create an empty set if the file does not exist
cache = set()
if os.path.exists(CACHE_FILE):
    with open(CACHE_FILE, 'r') as f:
        cache.update(line.strip() for line in f)


def checkFor
    # Check if the fetched data is already in the cache
    new_data = set(hostname) - cache

    # If new data exists, append it to the file and update the cache
    if new_data:
        with open('data.txt', 'a') as f:
            for item in new_data:
                f.write(item + '\n')
        cache.update(new_data)

        # Save the updated cache to the cache file
        with open(CACHE_FILE, 'w') as f:
            for item in cache:
                f.write(item + '\n')

