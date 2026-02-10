from app.core.database import logs_collection

async def save_log(log_data: dict):
    result = await logs_collection.insert_one(log_data)
    return str(result.inserted_id)
