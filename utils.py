import imports

#Data Loading - arff file type

data, meta = imports.arff.loadarff('/Users/ali/Downloads/phishing+websites/Training Dataset.arff')

# DataFrame type change from byte code to numeric

df=imports.pd.DataFrame(data)
str_df = df.select_dtypes([object])
str_df = str_df.stack().str.decode('utf-8').unstack()
df = str_df
for i in ['having_IP_Address', 'URL_Length', 'Shortining_Service',
       'having_At_Symbol', 'double_slash_redirecting', 'Prefix_Suffix',
       'having_Sub_Domain', 'SSLfinal_State', 'Domain_registeration_length',
       'Favicon', 'port', 'HTTPS_token', 'Request_URL', 'URL_of_Anchor',
       'Links_in_tags', 'SFH', 'Submitting_to_email', 'Abnormal_URL',
       'Redirect', 'on_mouseover', 'RightClick', 'popUpWidnow', 'Iframe',
       'age_of_domain', 'DNSRecord', 'web_traffic', 'Page_Rank',
       'Google_Index', 'Links_pointing_to_page', 'Statistical_report', 'Result']:
    df[i]=imports.pd.to_numeric(df[i], errors='coerce')
df[df['Result']==-1]=0

zero_df=df[df['Result']==0]
one_df=df[df['Result']==1]
zero_df['Result'] = 0
one_df=one_df[:4898]
df=zero_df
df=df.append(one_df)

df.to_excel('phising-uci-dataset.xlsx', header=True)