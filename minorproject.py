import streamlit as st
import pandas as pd
import xml.etree.ElementTree as ET
import plotly.express as px
import requests
import re

# Define global variables
S_sql = ""
xss_sql = ""
command_sql = ""

# Function to parse XML data for a specific host
def parse_xml(xml_data, target_host):
    global S_sql, xss_sql, command_sql
    root = ET.fromstring(xml_data)
    data = []
    for item in root.findall(".//item"):
        host = item.find("host").text
        http_request = item.find("request").text
        print("Request Data:")
        print(http_request)

        def detect_sql_injection(request):
            # Regular expression pattern to match SQL injection keywords and symbols
            sql_pattern = r'\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|EXEC|FROM|WHERE)\b|\b(?:\'(?:[^\'\\]|\\.)*\')\b'
            if re.search(sql_pattern, request, re.IGNORECASE):
                return True
            return False

        def detect_xss(request):
            # Regular expression pattern to match XSS payloads, HTML tags, and JavaScript functions
            xss_pattern = r'<(?:script|img|body|iframe|a|div|input)[^>]*>|javascript:|on\w+=["\'](?:[^"\'>]|\\["\'])*["\']'
            if re.search(xss_pattern, request, re.IGNORECASE):
                return True
            return False

        def detect_command_injection(request):
            # Regular expression pattern to match command injection symbols
            cmd_pattern = r'[|;&<>()$`]'
            if re.search(cmd_pattern, request):
                return True
            return False

        # Detect vulnerabilities in the HTTP request
        if detect_sql_injection(http_request):
            print("SQL Injection detected in request.")
            S_sql = "yes"
        if detect_xss(http_request):
            print("XSS detected in request.")
            xss_sql = "yes"
        if detect_command_injection(http_request):
            print("Command Injection detected in request.")
            command_sql = "yes"

        if host == target_host:
            url = item.find("url").text
            protocol = item.find("protocol").text
            method = item.find("method").text
            status = item.find("status").text
            response_length = item.find("responselength").text
            if response_length is not None:
                response_length = int(response_length)
            # Extract additional information: IP address, method, protocol, and cookie
            ip_element = item.find("host")
            ip_address = ip_element.get("ip") if ip_element is not None else None
            cookie_element = item.find("request/cookie")  # Adjusted here to correctly find the cookie
            cookie = cookie_element.text if cookie_element is not None else None
            data.append({
                "URL": url,
                "Host": host,
                "Protocol": protocol,
                "Method": method,
                "Status": status,
                "Response Length": response_length,
                "IP Address": ip_address,
                "Cookie": cookie
            })      
    return data

# Function to get geolocation information from IP address
def get_ip_info(ip_address):
    url = f"https://ipinfo.io/{ip_address}/json"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        return None

# Streamlit app
def main():
    # Add Burp Suite logo and title
    st.image("burp_logo.png", width=200)
    st.title("BURPSUITE LOGS VISUALIZER")

    # Set page background color and padding
    st.markdown(
        """
        <style>
        body {
            background-color: #f0f2f6;
            padding: 20px;
        }
        </style>
        """,
        unsafe_allow_html=True
    )

    # Text input for target host
    target_host = st.text_input("Enter the target host (e.g., www.example.com):")

    # File uploader for XML file
    uploaded_file = st.file_uploader("Upload an XML file", type=["xml"])

    if uploaded_file:
        xml_data = uploaded_file.read()
        parsed_data = parse_xml(xml_data, target_host)
        df = pd.DataFrame(parsed_data)

        # Display raw data
        st.subheader("Raw Data")
        st.write(df)

        # Display extracted IP address, method, protocol, and cookie
        st.subheader("Extracted Information")
        st.write(df[["IP Address", "Method", "Protocol", "Cookie"]])

        # Host Analysis (Bar chart)
        st.subheader("Host Analysis")
        fig_host = px.bar(df, x="Host", title="Host Analysis")
        st.plotly_chart(fig_host)

        # Path Analysis (Bar chart)
        st.subheader("Path Analysis")
        fig_path = px.bar(df, x="URL", title="Path Analysis")
        st.plotly_chart(fig_path)

        # Response Status Codes (Pie chart)
        st.subheader("Response Status Codes")
        fig_status = px.pie(df, names="Status", title="Response Status Codes")
        st.plotly_chart(fig_status)

        # Request Sizes (Histogram)
        st.subheader("Request Sizes")
        fig_request_sizes = px.histogram(df, x="Response Length", title="Request Sizes")
        st.plotly_chart(fig_request_sizes)

        # Response Sizes (Histogram)
        st.subheader("Response Sizes")
        fig_response_sizes = px.histogram(df, x="Response Length", title="Response Sizes")
        st.plotly_chart(fig_response_sizes)

        # Vulnerability Detection Indicator (Text label)
        st.subheader("Vulnerability Detection Indicator")
        if S_sql == "yes":
            st.error("SQL Injection detected!")
        if xss_sql == "yes":
            st.error("XSS detected!")
        if command_sql == "yes":
            st.error("Command Injection detected!")

        if S_sql !="yes" and xss_sql !="yes" and command_sql !="yes":
            st.success("No Vulnerability Detected!")

        # IP Address lookup based on extracted IP addresses
        ip_addresses = df["IP Address"].dropna().unique()
        ip_info_list = []
        for ip_address in ip_addresses:
            ip_info = get_ip_info(ip_address)
            if ip_info:
                ip_info_list.append({
                    "IP Address": ip_address,
                    "City": ip_info['city'],
                    "Region": ip_info['region'],
                    "Country": ip_info['country'],
                    "ISP": ip_info['org'],
                    "Lat": float(ip_info['loc'].split(',')[0]),
                    "Lon": float(ip_info['loc'].split(',')[1])
                })

        # Display IP information in a table
        if ip_info_list:
            ip_info_table = pd.DataFrame(ip_info_list)
            st.subheader("Geolocation Information")
            st.table(ip_info_table)

            # Visualize geolocation on a map
            fig_map = px.scatter_mapbox(
                ip_info_table,
                lat="Lat",
                lon="Lon",
                hover_name="IP Address",
                hover_data=["City", "Region", "Country", "ISP"],
                zoom=5
            )
            fig_map.update_layout(mapbox_style="open-street-map")
            st.plotly_chart(fig_map)

if __name__ == "__main__":
    main()
