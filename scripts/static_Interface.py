from nfstream import NFStreamer

def main():
    print("Reading flows from PCAP...\n")

    streamer = NFStreamer(
        source="datasets\packets\Capture_1.pcapng",
        statistical_analysis=True
    )

    for i, flow in enumerate(streamer):
        print(flow)

        if i >= 4:
            break

    print("\nDone.")


if __name__ == "__main__":
    main()