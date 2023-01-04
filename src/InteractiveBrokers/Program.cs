using InteractiveBrokers;

var httpClient = new HttpClient
{
    BaseAddress = new Uri("https://www.interactivebrokers.com/tradingapi/v1/")
};

var restClient = new IBRestClient(httpClient);
var response = await restClient.RequestTokenAsync("Hidden");

Console.WriteLine($"Response: {response}");

Console.ReadLine();
