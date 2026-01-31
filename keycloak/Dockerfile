FROM quay.io/keycloak/keycloak:24.0.5

ENV KC_HEALTH_ENABLED=true
ENV KC_METRICS_ENABLED=true
ENV KEYCLOAK_ADMIN=admin
ENV KEYCLOAK_ADMIN_PASSWORD=admin

COPY realm.json /opt/keycloak/data/import/realm.json

RUN /opt/keycloak/bin/kc.sh build

EXPOSE 3030

ENTRYPOINT ["/opt/keycloak/bin/kc.sh", "start-dev", "--http-port=3030", "--import-realm"]
