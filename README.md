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


## Port-forwarding services

When running in Kubernetes, expose services locally with:

```bash
kubectl port-forward svc/front-end -n demo-shop 3005:80        # Demo Shop UI
kubectl port-forward svc/detector -n demo 8001:8001            # detector API
kubectl port-forward svc/kube-prom-prometheus -n monitoring 9090
kubectl port-forward svc/kube-prom-grafana -n monitoring 3001:80
```

The backend uses `DEMO_SHOP_URL` and the React app uses `REACT_APP_SHOP_URL` to reach the shop at `http://localhost:3005`.

