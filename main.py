from fastapi import FastAPI, HTTPException, Depends,Header,Security
from pydantic import BaseModel,EmailStr
from database import db
from bson import ObjectId  #unique ids assigned to each doc in mongo db
from typing import List, Dict
from basemodel import ProfileSchema,InterviewTranscriptSchema,SignUpRequest,SignInRequest, TranscriptRequestBody, getTranscriptByCategoryRequestBody, getTranscriptByStatusRequestBody
from datetime import datetime, timezone,timedelta
import hashlib
from jose import jwt, JWTError
from jwt import PyJWTError
from fastapi.security import HTTPBearer
from fastapi.security.http import HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from typing import List

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

@app.post("/admin/login/")
async def sign_in(signin_request: SignInRequest):
    ALLOWED_EMAILS = {'sujalsahu0804@gmail.com', 'mitali@gmail.com', 'umang@gmail.com'}
    if signin_request.email in ALLOWED_EMAILS and signin_request.password=='InterAdminX@12345':
        user = db.profiles.find_one({"email": signin_request.email})

        if not user:
            raise HTTPException(status_code=400, detail="Invalid email or password.")

        hashed_password = hashlib.sha256(signin_request.password.encode()).hexdigest()
        if user["password"] != hashed_password:
            raise HTTPException(status_code=400, detail="Invalid email or password.")

        token_data = {
            "email": user["email"],
            "exp": datetime.now(timezone.utc) + timedelta(days=2)
        }
        token = jwt.encode(token_data, SECRET_KEY, algorithm="HS256")

        return {"authToken": token}
    else:
        raise HTTPException(status_code=400, detail="Invalid Credentials!!")

'''
# Endpoint for approving transcripts
@app.put("/admin/transcripts/approve/{transcript_id}")
async def approve_transcript(transcript_id: str):
    try:
        # Update the status of the transcript to "Approved"
        result = db.transcripts.update_one({"_id": ObjectId(transcript_id)}, {"$set": {"status": "Approved"}})
        
        # Check if the transcript was found and updated
        if result.modified_count == 0:
            raise HTTPException(status_code=404, detail="Transcript not found")
        
        return {"message": "Transcript approved successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail="An error occurred while approving transcript")


# Endpoint for rejecting transcripts
@app.put("/admin/transcripts/reject/{transcript_id}")
async def reject_transcript(transcript_id: str):
    try:
        # Update the status of the transcript to "Rejected"
        result = db.transcripts.update_one({"_id": ObjectId(transcript_id)}, {"$set": {"status": "Rejected"}})
        
        # Check if the transcript was found and updated
        if result.modified_count == 0:
            raise HTTPException(status_code=404, detail="Transcript not found")
        
        return {"message": "Transcript rejected successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail="An error occurred while rejecting transcript")
'''


@app.put("/admin/transcripts/approve/{transcript_slug}")
async def approve_transcript(transcript_slug: str):
    try:
        # Update the status of the transcript to "Approved"
        result = db.transcripts.update_one({"slug": transcript_slug}, {"$set": {"status": "Approved"}})
        
        # Check if the transcript was found and updated
        if result.modified_count == 0:
            raise HTTPException(status_code=404, detail="Transcript not found")
        
        return {"message": "Transcript approved successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail="An error occurred while approving transcript")



@app.put("/admin/transcripts/reject/{transcript_slug}")
async def reject_transcript(transcript_slug: str):
    try:
        # Update the status of the transcript to "Rejected"
        result = db.transcripts.update_one({"slug": transcript_slug}, {"$set": {"status": "Rejected"}})
        
        # Check if the transcript was found and updated
        if result.modified_count == 0:
            raise HTTPException(status_code=404, detail="Transcript not found")
        
        return {"message": "Transcript rejected successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail="An error occurred while rejecting transcript")


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


@app.post("/transcripts/get_transcripts_by_category_slug", response_model=List[InterviewTranscriptSchema])
async def get_transcripts_by_category_slug(reqBody: getTranscriptByCategoryRequestBody):
    try:
        transcripts = list(db.transcripts.find({"category_slug": reqBody.category_slug, "status": "Pending"}))
        if not transcripts:
            raise HTTPException(status_code=404, detail="Transcript not found")
        return transcripts
    except Exception as e:
        raise HTTPException(status_code=400, detail="Some Error Occurred: " + str(e))


@app.post("/transcripts/get_transcript_by_url_slug", response_model=InterviewTranscriptSchema)
async def get_transcript_by_url_slug(reqBody: getTranscriptByCategoryRequestBody):
    try:
        transcript = db.transcripts.find_one({"slug": reqBody.category_slug, "status": "Pending"})
        if not transcript:
            raise HTTPException(status_code=404, detail="Transcript not found")
        return transcript
    except Exception as e:
        raise HTTPException(status_code=400, detail="Some Error Occurred: " + str(e))
    
    
@app.post("/transcripts/get_transcripts_by_status", response_model=List[InterviewTranscriptSchema])
async def get_transcripts_by_status(reqBody: getTranscriptByStatusRequestBody):
    try:
        transcripts = list(db.transcripts.find({"status": reqBody.status}))
        if not transcripts:
            raise HTTPException(status_code=404, detail="Transcripts not found")
        return transcripts
    except Exception as e:
        raise HTTPException(status_code=400, detail="Some Error Occurred: " + str(e))



@app.delete("/transcripts/{transcript_slug}")
async def delete_transcript(transcript_slug: str):
    result = db.transcripts.delete_one({"slug": transcript_slug})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Transcript not found")
    return {"message": "Transcript deleted successfully"}


'''
@app.put("/transcripts/{transcript_slug}", response_model=InterviewTranscriptSchema)
async def update_transcript(transcript_slug: str, transcript: InterviewTranscriptSchema):
    result = db.transcripts.update_one({"slug": transcript_slug}, {"$set": transcript.dict()})
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Transcript not found")
    return {"message": "Transcript updated successfully"}
'''