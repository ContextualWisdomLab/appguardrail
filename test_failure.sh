echo "The strix failure happens on GitHub Actions runner. Looking at the error logs:"
echo "Strix run failed for model 'nvidia_nim/nvidia/llama-3.3-nemotron-super-49b-v1.5' after 81s (exit code 1)."
echo "Error during penetration test: loginAsGuest failed after 10 attempts: curl exit 7: curl: (7) Failed to connect to 127.0.0.1 port 48080 after 0 ms: Could not connect to server"
echo "It seems like a service Strix expects is not running on port 48080."
