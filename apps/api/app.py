from fastapi import FastAPI

app = FastAPI(title="IRYX API")


@app.get("/")
def root():
    return {
        "project": "IRYX",
        "status": "running"
    }
