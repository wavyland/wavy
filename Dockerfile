FROM scratch
LABEL maintainer="squat <lserven@gmail.com>"
ARG GOARCH
COPY bin/$GOARCH/wavy /wavy
ENTRYPOINT ["/wavy"]
