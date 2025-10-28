# Keycloak Troubleshooting Guide

This guide helps resolve common Keycloak startup issues, especially on Ubuntu servers.

## Quick Fix

If you're experiencing Keycloak startup issues, try the automated fix script:

```bash
make fix-keycloak
```

Or run directly:
```bash
./scripts/fix-keycloak.sh
```

## Common Issues and Solutions

### 1. Keycloak Fails to Start in Development Mode

**Error**: `ERROR: Failed to start server in (development) mode`

**Solutions**:

#### Option A: Use the Fix Script (Recommended)
```bash
make fix-keycloak
```

#### Option B: Manual Steps
```bash
# 1. Clean up existing containers
docker-compose down -v

# 2. Start PostgreSQL first
docker-compose up -d postgres

# 3. Wait for PostgreSQL to be ready (30-60 seconds)
docker-compose logs postgres

# 4. Start Keycloak
docker-compose up -d keycloak

# 5. Monitor Keycloak logs
make docker-logs-keycloak
```

### 2. Database Connection Issues

**Error**: `Connection refused` or `Database not ready`

**Solution**:
```bash
# Check PostgreSQL status
docker-compose ps postgres
docker-compose logs postgres

# Restart PostgreSQL if needed
docker-compose restart postgres

# Wait for it to be ready
docker-compose exec postgres pg_isready -U keycloak -d keycloak
```

### 3. Memory Issues

**Error**: `OutOfMemoryError` or container keeps restarting

**Solutions**:

1. **Increase Docker memory allocation** (Docker Desktop):
   - Go to Docker Desktop → Settings → Resources
   - Increase memory to at least 4GB

2. **For Ubuntu servers with limited memory**:
   ```bash
   # Add swap space
   sudo fallocate -l 2G /swapfile
   sudo chmod 600 /swapfile
   sudo mkswap /swapfile
   sudo swapon /swapfile
   ```

3. **Use production configuration** (uses less memory):
   ```bash
   make docker-up-prod
   ```

### 4. Port Conflicts

**Error**: `Port already in use` or `Address already in use`

**Solution**:
```bash
# Check what's using the ports
sudo netstat -tulpn | grep :8090
sudo netstat -tulpn | grep :5432

# Kill processes using the ports
sudo fuser -k 8090/tcp
sudo fuser -k 5432/tcp

# Or change ports in docker-compose.yml
```

### 5. Volume Permission Issues

**Error**: `Permission denied` when accessing volumes

**Solution**:
```bash
# Fix permissions
sudo chown -R $USER:$USER ./docker/keycloak/
chmod 644 ./docker/keycloak/realm-export.json

# Or run the fix script
make fix-keycloak
```

### 6. Realm Import Issues

**Error**: `Failed to import realm` or `Realm not found`

**Solutions**:

1. **Check realm file exists**:
   ```bash
   ls -la ./docker/keycloak/realm-export.json
   ```

2. **Validate JSON format**:
   ```bash
   cat ./docker/keycloak/realm-export.json | jq .
   ```

3. **Start without import first**:
   ```bash
   # Temporarily remove --import-realm from docker-compose.yml
   # Start Keycloak, then import manually via admin console
   ```

## Debugging Commands

### View Logs
```bash
# Keycloak logs
make docker-logs-keycloak

# PostgreSQL logs
make docker-logs-postgres

# All services logs
docker-compose logs
```

### Check Service Status
```bash
# Service status
docker-compose ps

# Health checks
docker-compose exec keycloak curl -f http://localhost:8080/health/ready
docker-compose exec postgres pg_isready -U keycloak -d keycloak
```

### Resource Usage
```bash
# Container resource usage
docker stats

# System resources
free -h
df -h
```

## Environment-Specific Solutions

### Ubuntu Server Issues

1. **Install required packages**:
   ```bash
   sudo apt update
   sudo apt install -y curl netcat-openbsd
   ```

2. **Configure firewall** (if enabled):
   ```bash
   sudo ufw allow 8090
   sudo ufw allow 5432
   ```

3. **Increase file limits**:
   ```bash
   echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
   echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf
   ```

### Docker on Ubuntu Issues

1. **Add user to docker group**:
   ```bash
   sudo usermod -aG docker $USER
   newgrp docker
   ```

2. **Start Docker service**:
   ```bash
   sudo systemctl start docker
   sudo systemctl enable docker
   ```

3. **Configure Docker daemon**:
   ```bash
   # Create or edit /etc/docker/daemon.json
   sudo tee /etc/docker/daemon.json <<EOF
   {
     "log-driver": "json-file",
     "log-opts": {
       "max-size": "10m",
       "max-file": "3"
     }
   }
   EOF
   
   sudo systemctl restart docker
   ```

## Performance Optimization

### For Production Servers

1. **Use production compose file**:
   ```bash
   make deploy-prod
   ```

2. **Optimize PostgreSQL**:
   ```bash
   # Add to docker-compose.yml postgres environment:
   - POSTGRES_SHARED_PRELOAD_LIBRARIES=pg_stat_statements
   - POSTGRES_MAX_CONNECTIONS=200
   - POSTGRES_SHARED_BUFFERS=256MB
   ```

3. **Optimize Keycloak**:
   ```bash
   # Add to docker-compose.yml keycloak environment:
   - JAVA_OPTS_APPEND=-Xms512m -Xmx1024m -XX:MetaspaceSize=96M -XX:MaxMetaspaceSize=256m
   ```

## Complete Reset (Nuclear Option)

If nothing else works, perform a complete reset:

```bash
# Stop everything
docker-compose down -v

# Remove all containers and volumes
make docker-clean-all

# Remove Docker images
docker rmi $(docker images -q)

# Start fresh
make deploy-dev
```

## Getting Help

1. **Check logs first**:
   ```bash
   make docker-logs-keycloak
   ```

2. **Run the fix script**:
   ```bash
   make fix-keycloak
   ```

3. **Check system resources**:
   ```bash
   free -h
   df -h
   docker stats
   ```

4. **Verify Docker installation**:
   ```bash
   docker --version
   docker-compose --version
   docker info
   ```

## Prevention

To avoid future issues:

1. **Always use the fix script** for initial setup
2. **Monitor system resources** regularly
3. **Keep Docker updated**
4. **Use specific image versions** (not `latest`)
5. **Implement proper health checks**
6. **Use production configurations** for production servers

## Support

If you continue to experience issues:

1. Run `make fix-keycloak` and share the output
2. Share logs: `make docker-logs-keycloak`
3. Share system info: `docker info` and `free -h`
4. Specify your Ubuntu version: `lsb_release -a`