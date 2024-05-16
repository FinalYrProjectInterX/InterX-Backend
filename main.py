from fastapi import FastAPI, HTTPException, Depends,Header,Security
from pydantic import BaseModel,EmailStr
from database import db
from bson import ObjectId  #unique ids assigned to each doc in mongo db
from typing import List, Dict, Any
from basemodel import ProfileSchema,InterviewTranscriptSchema,SignUpRequest,requestemail,SignInRequest, TranscriptRequestBody, getTranscriptByCategoryRequestBody, getTranscriptByStatusRequestBody,requestUserProfile,UpdateUserProfileRequest,UpdateTranscriptRequest, getTranscriptsOfUserReqBody
from datetime import datetime, timezone,timedelta
import hashlib
from jose import jwt, JWTError
from fastapi.security import HTTPBearer
from fastapi.security.http import HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from typing import List
import smtplib
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate
from emailer import EMAILER
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
    ALLOWED_EMAILS = {'admin@example.com'}
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


async def authenticate_user(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload
    except Exception as e:
        raise HTTPException(status_code=401, detail="Could not validate credentials")



@app.post("/profile", response_model=ProfileSchema)
async def get_user_profile(user_info: requestUserProfile):
    try:
        token = user_info.token

        # Check if token is provided
        if not token:
            raise HTTPException(status_code=401, detail="Token not provided in the request.")

        # Decode and validate token
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_email = payload["email"]

        # Retrieve user profile from the database based on the email
        user_profile = db.profiles.find_one({"email": user_email})
        if not user_profile:
            raise HTTPException(status_code=404, detail="User profile not found")

        return user_profile
    except JWTError as e:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        raise HTTPException(status_code=500, detail="An error occurred while fetching user profile")



@app.put("/profile/update")
async def update_user_profile(profile_info: UpdateUserProfileRequest):
    try:
        # Decode and validate token
        payload = jwt.decode(profile_info.token, SECRET_KEY, algorithms=["HS256"])
        user_email = payload["email"]

        # Fetch user from the database based on email
        user = db.profiles.find_one({"email": user_email})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Update user profile with new information
        update_fields = {}
        if profile_info.name != user["name"]:
            update_fields["name"] = profile_info.name
        if profile_info.about != user["about"]:
            update_fields["about"] = profile_info.about
        if profile_info.password != "":
            update_fields["password"] = profile_info.password  # Note: You may want to hash the password before updating

        if update_fields:
            db.profiles.update_one(
                {"email": user_email},
                {"$set": update_fields}
            )

        # Fetch updated user profile from the database
        updated_user = db.profiles.find_one({"email": user_email})
        updated_user_profile = ProfileSchema(**updated_user)
        return updated_user_profile
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        raise HTTPException(status_code=500, detail="An error occurred while updating user profile")
    
'''  
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
'''

@app.post("/transcripts/create_transcript")
async def create_transcript(transcript: TranscriptRequestBody):
    transcript = transcript.dict()
    token = transcript.get("token")
    if not token:
        raise HTTPException(status_code=401, detail="Token not provided in the request.")
    
    current_user = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    user_email = current_user["email"]  

    user_profile = db.profiles.find_one({"email": user_email})
    if not user_profile:
        raise HTTPException(status_code=404, detail="User profile not found")

    user_name = user_profile.get("name")

    transcript["user_name"] = user_name
    transcript["user_id"] = user_email
    transcript["date"] = datetime.utcnow().isoformat()
    transcript["status"] = "pending"
    print(transcript)
    result = db.transcripts.insert_one(transcript)

    return {"message": "Transcript Created successfully", "_id": str(result.inserted_id)}

@app.post("/transcripts/get_transcripts_by_category_slug", response_model=List[Dict[str, Any]])
async def get_transcripts_by_category_slug(reqBody: getTranscriptByCategoryRequestBody):
    try:
        transcripts = list(db.transcripts.find({"category_slug": reqBody.category_slug, "status": "Approved"}))
        print(transcripts)
        if not transcripts:
            raise HTTPException(status_code=404, detail="Transcripts not found")
        for transcript in transcripts:
            transcript['_id'] = str(transcript['_id'])
        return transcripts
    except Exception as e:
        raise HTTPException(status_code=400, detail="Some Error Occurred: " + str(e))
    
@app.post("/transcripts/get_transcripts_related_to_user", response_model=List[Dict[str, Any]])
async def get_transcripts_related_to_user(reqBody: getTranscriptsOfUserReqBody):
    try:
        transcripts = list(db.transcripts.find({"user_id": reqBody.email}))
        print(transcripts)
        for transcript in transcripts:
            transcript['_id'] = str(transcript['_id'])
        return transcripts
    except Exception as e:
        raise HTTPException(status_code=400, detail="Some Error Occurred: " + str(e))

@app.post("/transcripts/get_transcript_by_url_slug", response_model=Dict[str, Any])
async def get_transcript_by_url_slug(reqBody: getTranscriptByCategoryRequestBody):
    try:
        transcript = db.transcripts.find_one({"slug": reqBody.category_slug})
        if not transcript:
            raise HTTPException(status_code=404, detail="Transcript not found")
        transcript['_id'] = str(transcript['_id'])
        return transcript
    except Exception as e:
        raise HTTPException(status_code=400, detail="Some Error Occurred: " + str(e))
    
    
@app.post("/transcripts/get_transcripts_by_status", response_model=List[Dict[str, Any]])
async def get_transcripts_by_status(reqBody: getTranscriptByStatusRequestBody):
    try:
        transcripts = list(db.transcripts.find({"status": reqBody.status}))
        if not transcripts:
            raise HTTPException(status_code=404, detail="Transcripts not found")
        for transcript in transcripts:
            transcript['_id'] = str(transcript['_id'])
        return transcripts
    except Exception as e:
        raise HTTPException(status_code=400, detail="Some Error Occurred: " + str(e))
    
    
    
@app.post("/transcripts/update_transcript")
async def update_transcript(reqBody: UpdateTranscriptRequest):
    try:
        print(reqBody)
        transcript_object_id = ObjectId(reqBody.transcript_id)
        existing_transcript = db.transcripts.find_one({"_id": transcript_object_id})
        if not existing_transcript:
            raise HTTPException(status_code=404, detail="Transcript not found")

        # Update transcript fields
        update_data = {
            "$set": {
                "interview_experience": reqBody.interview_experience,
                "interview_tips": reqBody.interview_tips,
                "questions_answers": reqBody.questions_answers
            }
        }
        db.transcripts.update_one({"_id": transcript_object_id}, update_data)
        return {"message": "Transcript updated successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail="An error occurred while updating transcript")



@app.put("/transcripts/like/{transcript_id}", response_model=InterviewTranscriptSchema)
async def like_transcript(transcript_id: str):
    try:
        # Convert transcript_id to ObjectId
        transcript_object_id = ObjectId(transcript_id)

        # Retrieve the transcript from the database
        transcript = db.transcripts.find_one({"_id": transcript_object_id})
        if not transcript:
            raise HTTPException(status_code=404, detail="Transcript not found")

        # Increment the rating by 1
        transcript['rating'] += 1

        # Update the transcript in the database
        db.transcripts.update_one({"_id": transcript_object_id}, {"$set": {"rating": transcript['rating']}})

        # Convert ObjectId to string
        transcript['_id'] = str(transcript['_id'])

        # Return the updated transcript
        return transcript
    except Exception as e:
        raise HTTPException(status_code=500, detail="An error occurred while liking the transcript")


@app.delete("/transcripts/{transcript_id}")
async def delete_transcript(transcript_id: str):
    try:
        # Convert the transcript_id string to ObjectId
        transcript_object_id = ObjectId(transcript_id)

        # Check if the transcript exists in the database
        existing_transcript = db.transcripts.find_one({"_id": transcript_object_id})
        if not existing_transcript:
            raise HTTPException(status_code=404, detail="Transcript not found")

        # Delete the transcript from the database
        db.transcripts.delete_one({"_id": transcript_object_id})

        # Return a success message
        return {"message": "Transcript deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail="An error occurred while deleting transcript")
    
    

mail = EMAILER()

@app.put("/admin/transcripts/approve/{transcript_id}")
async def approve_transcript(transcript_id: str, user_email: requestemail):
    try:
        result = db.transcripts.update_one({"_id": ObjectId(transcript_id)}, {"$set": {"status": "Approved"}})
        
        if result.modified_count == 0:
            raise HTTPException(status_code=404, detail="Transcript not found")
        
        # Send email to user
        u_email= user_email.email
        print(u_email)
        subject = "Transcript Approval Notification"
        body = """<html>
    <body style="margin: 0; padding: 0; box-sizing: border-box; font-family: Arial, Helvetica, sans-serif;">
        <div style="width: 100%; background: #efefef; border-radius: 10px; padding: 10px;">
            <div style="margin: 0 auto; width: 90%; text-align: center;">
                <h2 style="background-color: rgb(20, 38, 66); padding: 10px 10px; border-radius: 3px; color: white;">Transcript Approval Notification!</h2>
                <div style="margin: 30px auto; background: white; width: 60%; border-radius: 10px; padding: 50px; text-align: center;">
                    <h3 style="margin-bottom: 30px; font-size: 20px; color: black;">Your transcript has been approved by the admin :)</h3>
                    <img src="https://static.vecteezy.com/system/resources/thumbnails/012/199/389/small_2x/thank-you-words-on-notepad-and-office-supplies-free-photo.jpg" alt="Approved Image" style="margin-bottom: 30px; max-width: 100%;">
                    <p style="margin-bottom: 30px; color: black;">Want to contribute more? Click below </p>
                    <a style="display: block; margin: 0 auto; border: none; background-color: rgb(15, 42, 100); color: white; width: 50%; line-height: 24px; padding: 10px; font-size: 20px; border-radius: 10px; cursor: pointer; text-decoration: none;"
                        href="inter-x-frontend.vercel.app/contribute"
                        target="_blank"
                    >
                        Let's Go
                    </a>
                </div>
            </div>
        </div>
    </body>
</html>
"""
        mail.send(subject,u_email,body)
        
        return {"message": "Transcript approved successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail="An error occurred while approving transcript")


@app.put("/admin/transcripts/reject/{transcript_id}")
async def reject_transcript(transcript_id: str, user_email: requestemail):
    try:
        # Update the status of the transcript to "Rejected"
        result = db.transcripts.update_one({"_id": ObjectId(transcript_id)}, {"$set": {"status": "Rejected"}})
        
        # Check if the transcript was found and updated
        if result.modified_count == 0:
            raise HTTPException(status_code=404, detail="Transcript not found")
        
        # Send email to user
        u_email= user_email.email
        subject = "Transcript Rejection Notification"
        body = """<html>
    <body style="margin: 0; padding: 0; box-sizing: border-box; font-family: Arial, Helvetica, sans-serif;">
        <div style="width: 100%; background: #efefef; border-radius: 10px; padding: 10px;">
            <div style="margin: 0 auto; width: 90%; text-align: center;">
                <h2 style="background-color: rgb(20, 38, 66); padding: 10px 10px; border-radius: 3px; color: white;">Transcript Rejection Notification!</h2>
                <div style="margin: 30px auto; background: white; width: 60%; border-radius: 10px; padding: 50px; text-align: center;">
                    <h3 style="margin-bottom: 30px; font-size: 18px; color: black;">Your transcript has been rejected by the admin!! Please attach a valid proof of your interview call.</h3>
                   
                    <p style="margin-bottom: 30px; color: black;">Contribute again? Click below </p>
                    <a style="display: block; margin: 0 auto; border: none; background-color: rgb(15, 42, 100); color: white; width: 50%; line-height: 24px; padding: 10px; font-size: 20px; border-radius: 10px; cursor: pointer; text-decoration: none;"
                        href="inter-x-frontend.vercel.app/contribute"
                        target="_blank"
                    >
                        Let's Go
                    </a>
                </div>
            </div>
        </div>
    </body>
</html>"""
        mail.send(subject,u_email,body)
        
        return {"message": "Transcript rejected successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail="An error occurred while rejecting transcript")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app)