from robot import Robot

def main():
    r = Robot()
    if r.connect("10.54.65.188"):
        print(f"Connected! Namespace: {r.namespace}")
        r.subscribe_pose()
        while True:
            if r.current_pose:
                print(f"Current Pose: {r.current_pose}")
            else:
                print("Waiting for pose...")
            import time
            time.sleep(2)
    else:
        print(f"Failed to connect: {r.last_error}")
    

if __name__ == "__main__":
    main()