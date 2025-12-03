using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.IO;

namespace DESApp.Data;

public static class BenchmarkDatabase
{
    private const string DB_PATH = "benchmark.db";

    public static void Init()
    {
        if (!File.Exists(DB_PATH))
        {
            SQLiteConnection.CreateFile(DB_PATH);

            using var con = new SQLiteConnection($"Data Source={DB_PATH}");
            con.Open();

            string createSql = @"
            CREATE TABLE Benchmark(
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                Algorithm TEXT,
                Operation TEXT,
                KeySize INTEGER,
                DataSize INTEGER,
                TimeMs REAL,
                Timestamp TEXT
            );";

            new SQLiteCommand(createSql, con).ExecuteNonQuery();
        }
    }

    public static void Insert(BenchmarkRecord r)
    {
        using var con = new SQLiteConnection($"Data Source={DB_PATH}");
        con.Open();

        string sql = @"INSERT INTO Benchmark
                       (Algorithm, Operation, KeySize, DataSize, TimeMs, Timestamp)
                       VALUES (@a,@o,@k,@d,@t,@time)";

        var cmd = new SQLiteCommand(sql, con);
        cmd.Parameters.AddWithValue("@a", r.Algorithm);
        cmd.Parameters.AddWithValue("@o", r.Operation);
        cmd.Parameters.AddWithValue("@k", r.KeySize);
        cmd.Parameters.AddWithValue("@d", r.DataSize);
        cmd.Parameters.AddWithValue("@t", r.TimeMs);
        cmd.Parameters.AddWithValue("@time", r.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"));
        cmd.ExecuteNonQuery();
    }

    public static List<BenchmarkRecord> GetAll()
    {
        var list = new List<BenchmarkRecord>();

        using var con = new SQLiteConnection($"Data Source={DB_PATH}");
        con.Open();

        string sql = "SELECT * FROM Benchmark";
        var cmd = new SQLiteCommand(sql, con);
        var reader = cmd.ExecuteReader();

        while (reader.Read())
        {
            list.Add(new BenchmarkRecord
            {
                Algorithm = reader["Algorithm"].ToString(),
                Operation = reader["Operation"].ToString(),
                KeySize = Convert.ToInt32(reader["KeySize"]),
                DataSize = Convert.ToInt32(reader["DataSize"]),
                TimeMs = Convert.ToDouble(reader["TimeMs"]),
                Timestamp = DateTime.Parse(reader["Timestamp"].ToString())
            });
        }

        return list;
    }
}
