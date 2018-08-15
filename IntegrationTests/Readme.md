# Run the tests

To run these tests you have to be outside of this directory. Just `cd ..`.
Now you can run the tests with:

```bash
pytest -v IntegrationTests
```

# Run the tests with docker

Just build it
```
docker build -t cowrie/test -f IntegrationTests.Dockerfile .
```

And run it
```
docker run \ 
    -v $(pwd):/app \ 
    -v /var/run/docker.sock:/var/run/docker.sock \  
    cowrie/test \
        pytest -v IntegrationTests
```
