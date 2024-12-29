from openai import OpenAI
from dotenv import load_dotenv
import os

# Load environment variables from .env
load_dotenv()

# Initialize OpenAI client
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def generate_ai_response(messages):
    """
    Generate an AI response using OpenAI's GPT-4 model.
    The messages parameter should be a list of dictionaries with 'role' and 'content'.
    Example:
        [
            {"role": "user", "content": "Hello, how are you?"},
            {"role": "assistant", "content": "I'm good, how can I help you today?"}
        ]
    """
    try:
        response = client.chat.completions.create(
            model="gpt-4",
            messages=messages
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Error generating AI response: {str(e)}"
