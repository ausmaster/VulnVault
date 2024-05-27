from json import load

from pymongo import MongoClient

with open("config.json", "r") as json_config:
    config = load(json_config)

print(config)
