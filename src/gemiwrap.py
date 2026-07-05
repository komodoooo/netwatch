import requests, json

class GeminiChat:
    def __init__(self, api_key:str, model:str="gemini-flash-latest"):
        self.api_key = api_key
        self.model = model
        self.endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
        self.headers = {
            "Content-Type": "application/json",
            "X-goog-api-key": self.api_key
        }
        self.history = []
    def get_models(self) -> set:
        response = requests.get("https://generativelanguage.googleapis.com/v1beta/models", headers=self.headers)
        if not response.ok:
            raise Exception(response.status_code, response.text)
        models = [m["name"] for m in response.json().get("models",[])]
        return set(models)
    def message(self, prompt: str) -> str:
        self.history.append({
            "role": "user",
            "parts": [{"text": prompt}]
        })
        payload = {"contents": self.history}
        response = requests.post(self.endpoint, headers=self.headers, json=payload)
        if not response.ok:
            raise Exception(response.status_code, response.text)
        data = response.json()
        try:
            answer = data["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError) as e:
            raise Exception("Error:", str(e), data)
        self.history.append({"role": "model","parts":[{"text": answer}]})
        return answer