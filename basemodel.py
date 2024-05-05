from pydantic import BaseModel, EmailStr,Field
from typing import Dict, List
from datetime import date, datetime

class ProfileSchema(BaseModel):
    name: str
    email: EmailStr
    about: str
    password: str

class requestUserProfile(BaseModel):
    token: str
    

class UpdateUserProfileRequest(BaseModel):
    token: str
    name: str
    email: EmailStr
    about: str
    password: str


class InterviewTranscriptSchema(BaseModel):
    user_id: str = ""
    interview_name: str = ""
    category: str = ""
    subCategory: str = ""
    optional_subject: str = ""
    gap_years: str = ""
    year_of_interview: str = ""
    specialization: str = ""
    work_experience: str = ""
    exam_scores: str = ""
    visa_type: str = ""
    country_applied_for_visa: str = ""
    purpose_of_travel: str = ""
    programming_languages: str = ""
    tech_stack_used: str = ""
    branch: str = ""
    commision_type: str = ""
    bank_name: str = ""
    interview_experience: str = ""
    interview_tips: str = ""
    rating: float = 0.0
    date: str = ""
    category_slug: str = ""
    slug: str = ""
    additional_info: str = ""
    status: str = "Pending"
    image_proof: str
    user_name: str
    questions_answers: List[Dict[str, str]] = []
    
class SignUpRequest(BaseModel):
    name: str
    email: EmailStr
    about: str
    password: str

class SignInRequest(BaseModel):
    email: EmailStr
    password: str

class TranscriptRequestBody(BaseModel):
    token: str
    interview_name: str
    category: str
    subCategory: str
    optional_subject: str
    gap_years: str
    year_of_interview: str
    specialization: str
    work_experience: str
    exam_scores: str
    visa_type: str
    country_applied_for_visa: str
    purpose_of_travel: str
    programming_languages: str
    tech_stack_used: str
    branch: str
    commision_type: str
    bank_name: str
    interview_experience: str
    interview_tips: str
    rating: float
    category_slug: str
    slug: str
    status: str
    image_proof: str
    questions_answers: List[Dict[str, str]]

class getTranscriptByCategoryRequestBody(BaseModel):
    category_slug: str
    
    

class getTranscriptByStatusRequestBody(BaseModel):
    status: str
    

class UpdateTranscriptRequest(BaseModel):
    transcript_id: str
    interview_name: str
    category: str
    subCategory: str
    optional_subject: str
    gap_years: str
    year_of_interview: str
    specialization: str
    work_experience: str
    exam_scores: str
    visa_type: str
    country_applied_for_visa: str
    purpose_of_travel: str
    programming_languages: str
    tech_stack_used: str
    branch: str
    commision_type: str
    bank_name: str
    interview_experience: str
    interview_tips: str
    rating: float
    category_slug: str
    slug: str
    status: str
    questions_answers: List[Dict[str, str]]