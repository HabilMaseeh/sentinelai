from motor.motor_asyncio import AsyncIOMotorClient

MONGO_URL = "mongodb://127.0.0.1:27017"

client = AsyncIOMotorClient(MONGO_URL)
db = client["sentinelai"]

logs_collection = db["logs"]
alerts_collection = db["alerts"]
ueba_profiles_collection = db["ueba_profiles"]
ueba_sessions_collection = db["ueba_sessions"]
ueba_user_profiles_collection = db["ueba_user_profiles"]
ueba_incidents_collection = db["ueba_incidents"]
