from nfstream import NFStreamer
import pandas as pd
from datetime import datetime
import glob
import os


def main():

    INTERFACE = r"\Device\NPF_{B6090C7A-F9DC-440D-8412-BB6CED82769D}"

    OUTPUT_DIR = "datasets/benign"

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    existing_files = glob.glob(f"{OUTPUT_DIR}/benign_flows_run*.csv")

    run_number = len(existing_files) + 1

    # ==============================
    # NFStream setup
    # ==============================
    streamer = NFStreamer(
        source=INTERFACE,
        statistical_analysis=True,
        active_timeout=60,
        idle_timeout=30
    )

    flows = []

    print("\n====================================")
    print("Live benign traffic capture started...")
    print("Press CTRL + C to stop")
    print("====================================\n")

    try:

        # Live flow capture
        for flow in streamer:
        
            flow_data = {}

            for key in flow.keys():

                try:
                    value = getattr(flow, key)

                    # Convert unsupported types safely
                    if value is None:
                        value = 0

                    flow_data[key] = value

                except Exception:
                    flow_data[key] = 0

            # Add label
            flow_data["Label"] = 0

            # Store flow
            flows.append(flow_data)

            # Live terminal output
            print(
                f"[FLOW {len(flows)}] "
                f"{flow.src_ip}:{flow.src_port} -> "
                f"{flow.dst_ip}:{flow.dst_port} | "
                f"Proto={flow.protocol} | "
                f"Packets={flow.bidirectional_packets} | "
                f"Bytes={flow.bidirectional_bytes}"
            )
    except KeyboardInterrupt:

        print("\nStopping capture...")

    df = pd.DataFrame(flows)

    # ==============================
    # Filename Generation
    # ==============================
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    filename = (
        f"{OUTPUT_DIR}/"
        f"benign_flows_run{run_number}_"
        f"{len(df)}flows_"
        f"{timestamp}.csv"
    )

    df.to_csv(filename, index=False)

    print("\n====================================")
    print(f"Saved {len(df)} flows")
    print(f"File: {filename}")
    print("====================================")


if __name__ == "__main__":
    main()













# from nfstream import NFStreamer
# import pandas as pd

# def main():

#     INTERFACE = r"\Device\NPF_{B6090C7A-F9DC-440D-8412-BB6CED82769D}"

#     streamer = NFStreamer(
#         source=INTERFACE,
#         statistical_analysis=True,
#         active_timeout=60,
#         idle_timeout=30
#     )

#     print("Capturing flows... Press CTRL+C to stop.")

#     df = streamer.to_pandas()

#     df["Label"] = 0

#     df.to_csv(rf"benign_flows_{len(df)}.csv", index=False)

#     print(f"Saved {len(df)} benign flows")

# if __name__ == "__main__":
#     main()





# from nfstream import NFStreamer

# def main():

#     streamer = NFStreamer(
#         source=r"\Device\NPF_{B6090C7A-F9DC-440D-8412-BB6CED82769D}",
#         promiscuous_mode=True,
#         statistical_analysis=True,
#     )

#     print("Listening for live traffic...\n")

#     count = 0

#     for flow in streamer:
#         print(flow)
#         count += 1

#         if count >= 5:
#             break

#     print("\nDone.")

# if __name__ == "__main__":
#     main()