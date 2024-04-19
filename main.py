from fastapi import FastAPI, HTTPException, Depends,Header,Security
from pydantic import BaseModel,EmailStr
from database import db
from bson import ObjectId  #unique ids assigned to each doc in mongo db
from typing import List, Dict
from basemodel import ProfileSchema,InterviewTranscriptSchema,SignUpRequest,SignInRequest, TranscriptRequestBody
from datetime import datetime, timezone,timedelta
import hashlib
from jose import jwt, JWTError
from jwt import PyJWTError
from fastapi.security import HTTPBearer
from fastapi.security.http import HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware

#from utils import authenticate_user


app = FastAPI(debug=True)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"], 
    allow_headers=["*"],  
)

SECRET_KEY = "mitali"

@app.post("/signup/")
async def sign_up(signup_request: SignUpRequest):
    print(signup_request)
    profile = signup_request
    print(profile)
    try:
        # Check if user with email already exists
        if db.profiles.find_one({"email": profile.email}):
            raise HTTPException(status_code=400, detail="A user with the same email already exists.")

        # Hash the password before saving
        hashed_password = hashlib.sha256(profile.password.encode()).hexdigest()

        # Save user to database
        db.profiles.insert_one({
            "name": profile.name,
            "email": profile.email,
            "about": profile.about,
            "password": hashed_password,
        })

        token_data = {
            "email": profile.email,
            "exp": datetime.now(timezone.utc)+ timedelta(days=2)
        }
        token = jwt.encode(token_data, SECRET_KEY, algorithm="HS256")

        return {"message": "User signed up successfully.", "authToken":token}
    except Exception as e:
        raise HTTPException(status_code=500, detail="An error occurred while signing up")


@app.post("/login/")
async def sign_in(signin_request: SignInRequest):
    try:
        user = db.profiles.find_one({"email": signin_request.email})

        if not user:
            raise HTTPException(status_code=400, detail="Invalid email or password.")

        # Verify password
        hashed_password = hashlib.sha256(signin_request.password.encode()).hexdigest()
        if user["password"] != hashed_password:
            raise HTTPException(status_code=400, detail="Invalid email or password.")

        # Generate JWT token
        token_data = {
            "email": user["email"],
            "exp": datetime.now(timezone.utc)+ timedelta(days=2)
        }
        token = jwt.encode(token_data, SECRET_KEY, algorithm="HS256")

        return {"authToken": token}
    except Exception as e:
        raise HTTPException(status_code=500, detail="An error occurred while logging in")


'''
@app.post("/transcripts/", response_model=InterviewTranscriptSchema)
async def create_transcript(transcript: InterviewTranscriptSchema):
    # Insert transcript into database
    result = db.transcripts.insert_one(transcript.dict())

    # Return the inserted transcript with its generated _id
    return {**transcript.dict(), "_id": str(result.inserted_id)}
  ''' 



async def authenticate_user(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload
    except PyJWTError as e:
        raise HTTPException(status_code=401, detail="Could not validate credentials")


@app.post("/transcripts/create_transcript")
async def create_transcript(
    transcript: TranscriptRequestBody):

    transcript = transcript.dict()
    print(transcript)
    token = transcript.get("token")
    print(token)
    if not token:
        raise HTTPException(status_code=401, detail="Token not provided in the request.")
    
    current_user = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    user_id = current_user["email"]  
    transcript_with_user_id = transcript
    transcript_with_user_id["user_id"] = user_id
    transcript_with_user_id["date"] = datetime.utcnow().isoformat()
    # Insert transcript into database
    result = db.transcripts.insert_one(transcript_with_user_id)

    # Return the inserted transcript with its generated _id
    return {"message":"Transcript Created successfully", "_id": str(result.inserted_id)}



@app.get("/transcripts/{transcript_id}", response_model=InterviewTranscriptSchema)
async def get_transcript(transcript_id: str):
    # Convert transcript_id to ObjectId
    try:
        transcript_oid = ObjectId(transcript_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid transcript ID")

    # Fetch transcript from the database
    transcript = db.transcripts.find_one({"_id": transcript_oid})

    # Check if transcript exists
    if not transcript:
        raise HTTPException(status_code=404, detail="Transcript not found")

    # Return the transcript
    return transcript

'''
@app.get("/transcripts/",response_model=List[InterviewTranscriptSchema])
async def get_transcripts():
    transcripts = list(db.transcripts.find())
    for transcript in transcripts:
        transcript['_id'] = str(transcript['_id'])
        transcript['user_id'] = str(transcript['user_id'])
    return transcripts
'''


@app.delete("/transcripts/{transcript_id}")
async def delete_transcript(transcript_id: str):
    result = db.transcripts.delete_one({"_id": ObjectId(transcript_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Transcript not found")
    return {"message": "Transcript deleted successfully"}



@app.put("/transcripts/{transcript_id}",response_model=InterviewTranscriptSchema)
async def update_transcript(transcript_id: str, transcript: InterviewTranscriptSchema):
    result = db.transcripts.update_one({"_id": ObjectId(transcript_id)}, {"$set": transcript})
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Transcript not found")
    return {"message": "Transcript updated successfully"}