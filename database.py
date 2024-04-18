# database.py

from pymongo import MongoClient
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Retrieve MongoDB connection URI from environment variables
MONGODB_URI = os.getenv("MONGODB_URI")

# Create a MongoDB client instance
client = MongoClient(MONGODB_URI)

# Specify the default database to use

db = client['Interx']
