from google import genai

client = genai.Client(api_key="AIzaSyAhBLFOUOdVpa2ellncQex5VDllwmJ5Avg")

try:
    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents="Hello, test message"
    )

    print("✅ API Key is working!")
    print(response.text)

except Exception as e:
    print("❌ Error:")
    print(e)
