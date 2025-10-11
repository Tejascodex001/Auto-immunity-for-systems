# Start from the official Nginx image
# Start from the official Nginx image
FROM nginx

# Switch to the root user ONLY for this RUN command
USER root

# Update package lists and install iptables
RUN apt-get update && apt-get install -y iptables

# DO NOT switch the user back here.
# Let the base image's entrypoint script handle running nginx as the correct user.