# Kubernetes Credential Stuffing Final Project

This repository contains the code used for the University of Essex thesis
project on defending against credential stuffing attacks.  The project is
split into three main parts:

* **backend/** – FastAPI application providing authentication, shopping and
  metrics endpoints.
* **frontend/** – React dashboard demonstrating the attacks and defences.
* **demo-shop/** – simple static shop used by the demos.

## Running the backend

```bash
pip install fastapi uvicorn sqlalchemy pydantic passlib[bcrypt] python-jose \
    numpy scikit-learn
uvicorn backend.app:app --reload
```

The frontend code can be integrated into any React build process and the demo
shop can be opened directly in a browser by loading `demo-shop/index.html`.

