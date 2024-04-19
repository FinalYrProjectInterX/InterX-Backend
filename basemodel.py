from pydantic import BaseModel, EmailStr,Field
from typing import Dict, List
from datetime import date, datetime

class ProfileSchema(BaseModel):
    name: str
    email: EmailStr
    about: str
    password: str


class InterviewTranscriptSchema(BaseModel):
    user_id: str
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
    programming_languages: List[str]
    tech_stack_used: List[str]
    problem_solving_approach: str
    branch: str
    commision_type: str
    bank_name: str
    selection_process_details: str
    interview_experience: str
    interview_tips: str
    rating: float
    date: str
    category_slug: str
    slug: str
    questions_answers: List[Dict[str, str]]
    
class SignUpRequest(BaseModel):
    name: str
    email: EmailStr
    about: str
    password: str

class SignInRequest(BaseModel):
    email: EmailStr
    password: str

class TranscriptRequestBody(BaseModel):
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
    programming_languages: List[str]
    tech_stack_used: List[str]
    problem_solving_approach: str
    branch: str
    commision_type: str
    bank_name: str
    selection_process_details: str
    interview_experience: str
    interview_tips: str
    rating: float
    category_slug: str
    slug: str
    questions_answers: List[Dict[str, str]]
