# Kubernetes Credential Stuffing Final Project

This repository contains the code used for the University of Essex thesis
project on defending against credential stuffing attacks.  The project is
split into three main parts:

* **backend/** – FastAPI application providing authentication, shopping and
  metrics endpoints.
* **dashboard/** – React dashboard demonstrating the attacks and defences.
* **shop-ui/** – simple static shop used by the demos.

## Running the backend

```bash
pip install fastapi uvicorn sqlalchemy pydantic passlib[bcrypt] python-jose \
    numpy scikit-learn
uvicorn backend.main:app --reload
```

## Running all services with Docker Compose

To start the backend API, React dashboard, and demo shop together run:

```bash
docker-compose up --build
```

This exposes the following services:

* Backend API – http://localhost:8000
* React dashboard – http://localhost:3000
* Demo shop – http://localhost:3001

## Requirements for the dashboard and shop

The React dashboard in `dashboard/` requires a Node.js environment with npm to
install dependencies (`npm install`) and run (`npm start`) if not using Docker.
The demo shop in `shop-ui/` is a static site that can be served by any web
server or opened directly in a browser via `shop-ui/index.html`.

