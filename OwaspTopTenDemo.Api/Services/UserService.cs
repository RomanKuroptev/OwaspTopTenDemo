using Microsoft.Data.Sqlite;
using System.Threading.Tasks;

namespace OwaspTopTenDemo.Api.Services
{
    public class UserService
    {
        private readonly string _connectionString = "Data Source=demo.db";

        public async Task<string> GetUserByNameSecureAsync(string userName)
        {
            var query = "SELECT * FROM Users WHERE Username = @Username";
            using (var connection = new SqliteConnection(_connectionString))
            {
                await connection.OpenAsync();
                var command = connection.CreateCommand();
                command.CommandText = query;
                command.Parameters.AddWithValue("@Username", userName); // Parameterized query

                var result = "";
                using (var reader = await command.ExecuteReaderAsync())
                {
                    while (await reader.ReadAsync())
                    {
                        result += $"Id: {reader.GetInt32(0)}, Username: {reader.GetString(1)}\n";
                    }
                }

                return result;
            }
        }

        public async Task<string> GetUserByNameAsync(string userName)
        {
            var query = $"SELECT * FROM Users WHERE Username = '{userName}'"; // String interpolation
            using (var connection = new SqliteConnection(_connectionString))
            {
                await connection.OpenAsync();
                var command = connection.CreateCommand();
                command.CommandText = query;

                var result = "";
                using (var reader = await command.ExecuteReaderAsync())
                {
                    while (await reader.ReadAsync())
                    {
                        result += $"Id: {reader.GetInt32(0)}, Username: {reader.GetString(1)}\n";
                    }
                }

                return result;
            }
        }

        public async Task<bool> RegisterUserInsecureAsync(string username, string password, string role)
        {
            using (var connection = new SqliteConnection(_connectionString))
            {
                await connection.OpenAsync();
                var command = connection.CreateCommand();
                command.CommandText = @"
            INSERT INTO Users (Username, Password, Role) VALUES (@username, @password, @role);
        ";
                command.Parameters.AddWithValue("@username", username);
                command.Parameters.AddWithValue("@password", password); // Insecure: storing plain text password
                command.Parameters.AddWithValue("@role", role);

                var result = await command.ExecuteNonQueryAsync();
                return result > 0;
            }
        }



        public async Task<bool> RegisterUserSecureAsync(string username, string password, string role)
        {
            using (var connection = new SqliteConnection(_connectionString))
            {
                await connection.OpenAsync();
                var command = connection.CreateCommand();
                command.CommandText = @"
                INSERT INTO Users (Username, PasswordHash, Role) VALUES (@username, @passwordHash, @role);
            ";
                command.Parameters.AddWithValue("@username", username);
                command.Parameters.AddWithValue("@passwordHash", BCrypt.Net.BCrypt.HashPassword(password)); // Secure: storing hashed password
                command.Parameters.AddWithValue("@role", role);

                var result = await command.ExecuteNonQueryAsync();
                return result > 0;
            }
        }

        public async Task<string> GetSensitiveDataAsync()
        {
            // Implementation to get sensitive data
            return "Sensitive Data";
        }

        public async Task<(bool IsValid, string Role)> ValidateUserAsync(string username, string password)
        {
            var query = "SELECT Password, PasswordHash, Role FROM Users WHERE Username = @Username";
            using (var connection = new SqliteConnection(_connectionString))
            {
                await connection.OpenAsync();
                var command = connection.CreateCommand();
                command.CommandText = query;
                command.Parameters.AddWithValue("@Username", username);

                using (var reader = await command.ExecuteReaderAsync())
                {
                    if (await reader.ReadAsync())
                    {
                        var storedPassword = reader.IsDBNull(0) ? null : reader.GetString(0);
                        var storedPasswordHash = reader.IsDBNull(1) ? null : reader.GetString(1);
                        var role = reader.IsDBNull(2) ? null : reader.GetString(2);

                        if (!string.IsNullOrEmpty(storedPasswordHash) && BCrypt.Net.BCrypt.Verify(password, storedPasswordHash))
                        {
                            return (true, role);
                        }
                        else if (storedPassword == password)
                        {
                            return (true, role);
                        }
                    }
                }
            }
            return (false, null);
        }




    }
}
